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
    AggregateScope, BeginClaimedTextGenerationCommit, BeginTextGenerationCommit, Clock, ClockError,
    CommandCommit, CommitError, CommitResult, ConversationCommit, ConversationCommitResult,
    ConversationLoadedStream, ConversationReceipt, ConversationReceiptLookup,
    ConversationRepository, ConversationTextRepository, EventStore as AppEventStore,
    EventStoreError, FinishTextGenerationCommit, IdGenerationError, IdGenerator, IdempotencyScope,
    LoadedStream, OperationTag, ReceiptLookup, RejectTextGenerationCommit, ReplayEvent,
    RuntimeAuthorityId, StorageFailureKind, TaskRunAssignmentIdentity, TextGenerationCommitResult,
    TextGenerationPhase, TextGenerationReceipt, TextGenerationReceiptLookup, UnitOfWork,
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
use runne_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use runne_domain::timestamp::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};

/// Immutable D2 identity expected when replaying a completed Conversation receipt.
#[derive(Debug, Clone)]
pub struct D2ToolLoopCompletionReplayBinding {
    pub command_id: CommandId,
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub cycle_id: runne_domain::id::CycleId,
    pub taskrun_head: u64,
    pub evaluation_ref: runne_domain::verification::PlanEvaluationRef,
    pub terminal_attempt_id: [u8; 16],
    pub terminal_outbox_id: [u8; 16],
    pub terminal_sequence: u64,
    pub settlement_digest: IntegrityDigest,
    pub terminal_sources: Vec<runne_application::ports::D2ToolTerminalSourceV1>,
    pub assistant_message_id: MessageId,
    pub assistant_text_digest: IntegrityDigest,
    pub assistant_text_length: u64,
    pub completed_receipt: TextGenerationReceipt,
}

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

pub(crate) use conversation::has_no_active_generation_before_global_position;
pub(crate) use taskrun_local_command::effects_proof::{
    LocalEffectsProofRequest, terminal_stop_proven,
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
    // Close the reader first so the final writer close can clean up WAL sidecars.
    reader: Mutex<ManagedConnection>,
    writer: Mutex<ManagedConnection>,
    id_counter: AtomicU64,
    permission_owner: Option<core::RegisteredPermissionOwnerPair>,
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
pub(crate) mod commit_gate;
mod component_guard;
mod conversation;
pub use conversation::ConversationStreamHealth;
pub(crate) use conversation::load_conversation_from_connection;
mod conversation_writer_lease_host;
mod core;
mod correlation;
mod d2_completion_recovery;
mod d2_failure_recovery;
mod enrollment_launch;
mod event_context;
mod event_guard;
mod events;
mod ids;
mod parse_helpers;
mod position_helpers;
pub mod process;
pub mod provider_failure_recovery;
mod provider_terminal;
mod provider_terminal_resolver;
pub(crate) mod snapshot;
mod taskrun_assignment;
pub use d2_completion_recovery::{D2CompletionRecoveryCandidate, D2CompletionRecoveryPage};
pub use d2_failure_recovery::{D2FailureRecoveryCandidate, D2FailureRecoveryPage};
mod permission_modes;
mod taskrun_cancellation_completion;
mod taskrun_cancellation_scan;
pub(crate) mod taskrun_claim;
mod taskrun_execution_input;
pub(crate) mod taskrun_local_command;
pub mod taskrun_tool_invocation;
pub use permission_modes::{
    ClosedRulesManagedIdentityV2, FullAccessChallengeRequest, IssuedFullAccessChallenge,
    IssuedFullAccessChallengeContext, LegacyRecordIdentityV1, ManagedIdentityChallengeBindingV2,
    ManagedIdentityMetadata, NativeModeConfirmationRequestV2, PermissionModeAuthorityContext,
    PermissionModeCeremonyStatusV2, PermissionModeSelectionManagedIdentity,
    PermissionModeSelectionSnapshot, PermissionModeStoreError, ProtectedNativeLaunchContext,
};
#[cfg(target_os = "linux")]
pub use taskrun_local_command::LocalCommandPermissionTerminalOutputV1;
pub use taskrun_local_command::{
    LocalCommandApprovalBinding, LocalCommandAttemptState, LocalCommandCancellationStopEvidence,
    LocalCommandPermissionCaptureV1, LocalCommandPermissionRoute, LocalCommandRecoveryCandidate,
    PermissionRootFenceGuardV1, PermissionRootFenceOwnerV1, PermissionRootFenceRequestV1,
};
mod taskrun_no_effect_proof;
pub(crate) use taskrun_no_effect_proof::authenticated_local_denial;
mod taskrun_no_effect_scan;
mod taskrun_provider_binding;
mod taskrun_provider_round_binding;
pub(crate) mod taskrun_provider_start;
mod taskrun_queue_scan;
mod taskrun_release;
pub(crate) mod taskrun_started_generation;
pub(crate) mod taskrun_submit_origin;
pub(crate) mod terminal_cancellation_receipt;
pub(crate) mod test_support_diagnostics;
mod text;

pub(crate) fn verify_d2_cancelled_provider_rounds(
    connection: &rusqlite::Connection,
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
    evidence: runne_application::ports::D2ToolLoopCancellationEvidence,
    original_claim_version: u64,
    cancel_version: u64,
) -> Result<(), CommitError> {
    text::verify_d2_cancelled_provider_rounds(
        connection,
        taskrun_id,
        attempt_id,
        evidence,
        original_claim_version,
        cancel_version,
    )
}

pub(crate) mod text_receipt_helpers;
mod text_validation_helpers;
mod unit_of_work;
mod unknown_successor;

use correlation::StoredCorrelationType;
pub use enrollment_launch::EnrollmentLaunchGenerationError;
pub use unknown_successor::SqliteUnknownSuccessorRepository;

#[cfg(test)]
mod enrollment_launch_tests;
#[cfg(test)]
#[path = "store/tests.rs"]
mod tests;
