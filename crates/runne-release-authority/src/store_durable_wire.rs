//! Canonical scalar-only wire projection for the durable fixture promotion store.
#![allow(clippy::redundant_pub_crate)] // Global durable authority consumes the byte decoder.
use crate::store::CommandFingerprint;
use crate::{
    AuthorityError, CandidateBinding, PromotionId, PromotionState, ThresholdFixtureStoreBinding,
    TransactionOutcome,
};
use serde::{Deserialize, Serialize};
#[path = "store_durable_wire_claim.rs"]
mod claim;
#[path = "store_durable_wire_stage_claims.rs"]
mod stage_claims;
use claim::{StageClaimWire, stage_claims};
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Canonical per-promotion scalar projection embedded only by durable fixture ledgers.
pub struct FileState {
    schema_version: String,
    bootstrap: String,
    profile: String,
    version: u64,
    promotion: String,
    record: RecordWire,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordWire {
    authority_instance: String,
    state: String,
    revision: u64,
    binding: BindingWire,
    admission: Option<AdmissionWire>,
    rc1: Option<StageWire>,
    rc2: Option<StageWire>,
    rc2_effect: Option<EffectAuthorizationWire>,
    inventory: Option<String>,
    metadata: Option<String>,
    report: Option<String>,
    reservation: Option<ReservationWire>,
    stage_reservation: Option<StageReservationWire>,
    stage_claims: Vec<StageClaimWire>,
    stage_trust_now: u64,
    stage_trust_utc: String,
    stage_trust_root_epoch: u64,
    stage_trust_role_floor: u64,
    rc2_evidence_now: u64,
    rc2_evidence_revocation_epoch: u64,
    rc2_evidence_generation: u64,
    rc2_evidence_keys: Vec<EvidenceKeyWire>,
    threshold_admission: Option<String>,
    outbox: Option<OutboxWire>,
    ack: Option<AckWire>,
    commands: Vec<CommandWire>,
    completed_verify: Vec<CompletedWire>,
    previous_snapshot: Option<String>,
    snapshot: Option<SnapshotWire>,
    publication: PublicationWire,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    subject: String,
    matrix: String,
    bootstrap: String,
    candidate: String,
    policy: String,
    release_facts: Option<String>,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionWire {
    unsigned: String,
    manifest: String,
    release_facts: crate::wire::ReleaseFacts,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StageWire {
    sha256: String,
    bootstrap: String,
    issuer: IdentityWire,
    root: IdentityWire,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectAuthorizationWire {
    authority_instance: String,
    promotion: String,
    revision: u64,
    authorization: String,
    namespace: String,
    generation: u64,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
    workflow: String,
    signer: String,
    runner: String,
    slots: Vec<EffectSlotWire>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectSlotWire {
    slot: String,
    digest: String,
    length: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityWire {
    principal: String,
    account: String,
    lane: String,
    key: String,
    signature_profile: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationWire {
    authority_instance: String,
    promotion: String,
    revision: u64,
    authorization: String,
    command: String,
    fingerprint: String,
    commitment: String,
    evidence_now: u64,
    evidence_revocation_epoch: u64,
    evidence_generation: u64,
    evidence_registrations_digest: String,
    evidence_expires_at: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyWire {
    principal: String,
    account: String,
    lane: String,
    key: String,
    signature_profile: String,
    public_key: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StageReservationWire {
    promotion: String,
    revision: u64,
    command: String,
    kind: String,
    fingerprint: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OutboxWire {
    state: String,
    admission: String,
    revision: u64,
    command: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AckWire {
    admission: String,
    claim_revision: u64,
    command: String,
    fingerprint: String,
    outcome: OutcomeWire,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommandWire {
    command: String,
    fingerprint: String,
    outcome: OutcomeWire,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletedWire {
    command: String,
    revision: u64,
    commitment: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OutcomeWire {
    state: String,
    revision: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    bytes: String,
    digest: String,
    revision: u64,
}
#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct PublicationWire {
    manifest: Option<String>,
    authorization: Option<String>,
    destination: Option<String>,
    channel: Option<String>,
    namespace: Option<String>,
    executor: Option<String>,
    lane: Option<String>,
    workflow: Option<String>,
    valid_from: Option<u64>,
    expires_at: Option<u64>,
    revocation_epoch: Option<u64>,
}

#[path = "store_durable_wire_consistency.rs"]
mod consistency;
#[path = "store_durable_wire_facts.rs"]
mod facts;
#[path = "store_durable_wire_read.rs"]
mod read;
#[path = "store_durable_wire_record.rs"]
mod record;
#[path = "store_durable_wire_snapshot.rs"]
mod snapshot;
#[path = "store_durable_wire_write.rs"]
mod write;
pub(crate) use read::bytes;
pub use read::encode;
use read::{h, opt, outbox, outcome, stage, state};
pub use write::from_record;
pub fn decode(
    bytes: &[u8],
    binding: &ThresholdFixtureStoreBinding,
) -> Result<(PromotionId, crate::store_machine::Record), AuthorityError> {
    read::decode(bytes, binding)
}

/// Decode one embedded canonical promotion projection under its immutable binding.
pub fn into_record(
    file: &FileState,
    binding: &ThresholdFixtureStoreBinding,
) -> Result<(PromotionId, crate::store_machine::Record), AuthorityError> {
    read::into_record(file, binding)
}
