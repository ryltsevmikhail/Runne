//! Store — SQLite-backed persistence adapter.
//!
//! Provides:
//! - [`StoreTransaction`] — opens, configures, and migrates the database
//! - [`EventStore`] impl — loads task run event streams
//! - [`UnitOfWork`] impl — idempotency lookup + atomic commit
//! - [`IdGenerator`] impl — UUIDv7-based unique IDs
//! - [`Clock`] impl — system wall clock in microseconds

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, BeginTextGenerationCommit, Clock, ClockError, CommandCommit, CommitError,
    CommitResult, ConversationCommit, ConversationCommitResult, ConversationLoadedStream,
    ConversationReceipt, ConversationReceiptLookup, ConversationRepository,
    ConversationTextRepository, EventStore as AppEventStore, EventStoreError,
    FinishTextGenerationCommit, IdGenerationError, IdGenerator, IdempotencyScope, LoadedStream,
    OperationTag, ReceiptLookup, RejectTextGenerationCommit, ReplayEvent, RuntimeAuthorityId,
    StorageFailureKind, TextGenerationCommitResult, TextGenerationPhase, TextGenerationReceipt,
    TextGenerationReceiptLookup, UnitOfWork,
};
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use runne_application::replay_service::{
    measured_conversation_replay_event_bytes, measured_taskrun_replay_event_bytes,
    validate_replay_writer_event_size,
};
use runne_domain::conversation::ConversationEvent;
use runne_domain::event::{Actor, EventEnvelope, Sensitivity, UncommittedEvent};
use runne_domain::id::{
    AggregateId, AttemptId, CommandId, ConversationId, EventId, IntegrityDigest, MessageId,
    TaskRunId,
};
use runne_domain::task_run::TaskRunEvent;
use runne_domain::timestamp::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};

use crate::codec::{
    CommandOutcomeCodec, ConversationEventCodec, ConversationReceiptCodec, IdempotencyScopeCodec,
    StoreCodec, TaskRunEventCodec, TextGenerationReceiptCodec,
};
use crate::integrity::{
    compute_integrity_digest_v2_with_global_position, compute_integrity_digest_with_global_position,
};
use crate::schema::{
    ConnectionMode, ManagedConnection, apply_migrations, open_managed_connection,
    publication_from_managed, readiness_from_managed,
};

/// Maximum event count per commit (safety bound).
const MAX_EVENTS_PER_COMMIT: usize = 1_000;

const CORRELATION_TYPE_TASK_RUN: i64 = 1;
const CORRELATION_TYPE_CONVERSATION: i64 = 2;
const INTEGRITY_PROFILE_V1: i64 = 1;
const INTEGRITY_PROFILE_V2: i64 = 2;

fn stored_sensitivity(value: i64) -> Result<Sensitivity, EventStoreError> {
    match value {
        0 => Ok(Sensitivity::Public),
        1 => Ok(Sensitivity::Internal),
        2 => Ok(Sensitivity::Sensitive),
        _ => Err(EventStoreError::CorruptData),
    }
}

const fn sensitivity_value(value: Sensitivity) -> i64 {
    match value {
        Sensitivity::Public => 0,
        Sensitivity::Internal => 1,
        Sensitivity::Sensitive => 2,
    }
}

/// Inner state shared between clones via `Arc`.
struct StoreInner {
    writer: Mutex<ManagedConnection>,
    reader: Mutex<ManagedConnection>,
    id_counter: AtomicU64,
}

/// SQLite-backed store with a single writer connection.
///
/// Implements [`AppEventStore`], [`UnitOfWork`], [`IdGenerator`], and [`Clock`].
/// Safe to clone — clones share the same connections via `Arc`.
///
/// # Concurrency
///
/// All writes go through a single `Mutex<Connection>`. Reads (loads, receipt
/// lookups) use a separate read connection to avoid blocking the writer.
#[derive(Clone)]
pub struct StoreTransaction {
    inner: Arc<StoreInner>,
    runtime_authority_id: RuntimeAuthorityId,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

/// Current time as Unix microseconds (for stream row creation).
fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

mod append_helpers;
mod clock;
#[cfg(feature = "test-support")]
mod commit_gate;
mod component_guard;
mod conversation;
pub use conversation::ConversationStreamHealth;
mod core;
mod correlation;
mod enrollment_launch;
mod event_context;
mod event_guard;
mod events;
mod ids;
mod parse_helpers;
mod position_helpers;
pub mod process;
mod provider_terminal;
pub(crate) mod snapshot;
mod taskrun_assignment;
pub(crate) mod taskrun_claim;
mod taskrun_execution_input;
mod taskrun_provider_binding;
mod taskrun_queue_scan;
mod taskrun_release;
mod text;
mod text_receipt_helpers;
mod text_validation_helpers;
mod unit_of_work;

use correlation::StoredCorrelationType;
pub use enrollment_launch::EnrollmentLaunchGenerationError;

#[cfg(test)]
mod enrollment_launch_tests;
#[cfg(test)]
#[path = "store/tests.rs"]
mod tests;
