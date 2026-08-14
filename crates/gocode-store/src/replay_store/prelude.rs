use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use gocode_application::ports::{
    ReplayError, ReplayEvent, ReplayOpenResult, ReplayRetentionBaselineCandidateV1,
    ReplayRetentionBaselineCandidateV2, ReplayRetentionBaselineCandidateV2Parts, ReplaySession,
    ReplayState, ReplayStorePort,
};
use gocode_application::replay_service::{
    ReplayDeliveryPrecommitGuard, measured_conversation_replay_event_bytes,
    measured_taskrun_replay_event_bytes,
};
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{
    AggregateId, CommandId, ConversationId, EventId, EventLogLineageId, IdempotencyKey,
    IntegrityDigest, TaskRunId,
};
use gocode_domain::replay::{GapRangeRef, ReplayCursor, ReplayScope, RetentionManifest};
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension, params};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};
use crate::integrity::{
    compute_integrity_digest_v2_with_global_position, compute_integrity_digest_with_global_position,
};
use crate::schema::ManagedConnection;

// ── HMAC ─────────────────────────────────────────────────────────────────────

type HmacSha256 = Hmac<Sha256>;
const HIGH_WATER_REF_SCHEMA_VERSION: u32 = 1;
const RETENTION_GENERATION: u64 = 0;

fn published_retention_generation(internal_generation: u64) -> Result<u64, ReplayError> {
    internal_generation
        .checked_add(1)
        .ok_or_else(|| ReplayError::Integrity("published retention generation overflow".to_owned()))
}

/// Build a 77-byte HMAC-protected `HighWaterRef`.
///
/// Layout: `authority_id[16] || floor_present[1] || retained_floor[8u64be] ||
/// retention_generation[8u64be] || ref_schema_version[4u32be] ||
/// global_position[8u64be] || proof[32]`.
///
/// The proof is `HMAC-SHA256(server_secret, all preceding fields || session_id[16])`.
fn build_high_water_ref(
    authority_id: &[u8; 16],
    floor: Option<i64>,
    global_position: i64,
    server_secret: &[u8; 32],
    session_id: &[u8; 16],
) -> Vec<u8> {
    let floor_present = if floor.is_some() { 1u8 } else { 0u8 };
    let floor_bytes = (floor.unwrap_or(0) as u64).to_be_bytes();
    let gen_bytes = 0u64.to_be_bytes(); // retention_generation = 0
    let schema_bytes = HIGH_WATER_REF_SCHEMA_VERSION.to_be_bytes();
    let pos_bytes = (global_position as u64).to_be_bytes();

    let mut msg = Vec::with_capacity(16 + 1 + 8 + 8 + 4 + 8 + 16);
    msg.extend_from_slice(authority_id);
    msg.push(floor_present);
    msg.extend_from_slice(&floor_bytes);
    msg.extend_from_slice(&gen_bytes);
    msg.extend_from_slice(&schema_bytes);
    msg.extend_from_slice(&pos_bytes);
    msg.extend_from_slice(session_id);

    let mut mac = HmacSha256::new_from_slice(server_secret).unwrap();
    mac.update(&msg);
    let proof = mac.finalize().into_bytes();

    let mut hw = Vec::with_capacity(77);
    hw.extend_from_slice(authority_id);
    hw.push(floor_present);
    hw.extend_from_slice(&floor_bytes);
    hw.extend_from_slice(&gen_bytes);
    hw.extend_from_slice(&schema_bytes);
    hw.extend_from_slice(&pos_bytes);
    hw.extend_from_slice(&proof);
    hw
}

struct RetainedInventory {
    events: Vec<ReplayEvent>,
    interior_gap: Option<(i64, i64)>,
}
