//! Application ports — abstract traits for persistence, identity, and time.
//!
//! All ports are trait-only; no concrete adapters in this crate.

use gocode_domain::agent_loop::{StepOutcomeRef, WakeCondition, WakeEvidenceRef};
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::event::{EventEnvelope, UncommittedEvent};
use gocode_domain::id::{
    AttemptId, CheckpointId, CommandId, ConversationId, CycleId, EventId, IdempotencyKey,
    IntegrityDigest, PlanEvaluationId, TaskRunId, WorkspaceId,
};
use gocode_domain::recovery::ReconciliationResultRef;
use gocode_domain::reference::BudgetReservationRef;
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;
use gocode_domain::verification::PlanEvaluationRef;

use crate::commands::CommandOutcome;
use crate::fingerprint::CommandFingerprint;

// ── EventStore ──────────────────────────────────────────────────────────────

/// Reads committed event streams for an aggregate.
pub trait EventStore {
    /// Load the full committed event stream for a task run.
    ///
    /// Returns a [`LoadedStream`] or an [`EventStoreError`].
    fn load_task_run(&self, taskrun_id: TaskRunId) -> Result<LoadedStream, EventStoreError>;
}

/// Atomic persistence boundary for conversation streams and create receipts.
pub trait ConversationRepository {
    /// Loads a committed conversation stream.
    fn load_conversation(
        &self,
        conversation_id: ConversationId,
    ) -> Result<ConversationLoadedStream, EventStoreError>;

    /// Looks up the durable result of a create-conversation command.
    fn lookup_conversation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<ConversationReceiptLookup, CommitError>;

    /// Atomically appends conversation events and stores their create receipt.
    fn commit_conversation(
        &self,
        payload: ConversationCommit,
    ) -> Result<ConversationCommitResult, CommitError>;
}

/// A committed conversation stream.
#[derive(Debug, Clone)]
pub struct ConversationLoadedStream {
    /// Events ordered by their contiguous stream sequence.
    pub events: Vec<EventEnvelope<ConversationEvent>>,
    /// Last committed stream sequence, or zero for an empty stream.
    pub current_version: u64,
    /// Last committed event identity, if any.
    pub last_event_id: Option<EventId>,
}

/// Durable result of a create-conversation command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationReceipt {
    /// Conversation created by the command.
    pub conversation_id: ConversationId,
    /// Workspace recorded by the creation event.
    pub workspace_id: WorkspaceId,
    /// Resulting stream version.
    pub new_version: u64,
    /// Persistence-authoritative commit timestamp.
    pub committed_at: Timestamp,
}

/// Result of a conversation receipt lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationReceiptLookup {
    /// No matching receipt exists.
    Miss,
    /// The exact command was committed previously.
    Duplicate {
        /// Original durable result.
        stored_result: ConversationReceipt,
    },
}

/// Atomic conversation event and receipt commit payload.
#[derive(Debug, Clone)]
pub struct ConversationCommit {
    /// Unique command identity.
    pub command_id: CommandId,
    /// Client-provided idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Full uniqueness scope for the key.
    pub idempotency_scope: IdempotencyScope,
    /// Deterministic semantic command fingerprint.
    pub command_fingerprint: CommandFingerprint,
    /// Expected conversation stream version.
    pub expected_version: u64,
    /// Conversation events to append.
    pub events: Vec<UncommittedEvent<ConversationEvent>>,
    /// Workspace expected in the creation event and receipt.
    pub workspace_id: WorkspaceId,
}

/// Result of an atomic conversation commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationCommitResult {
    /// Events and receipt were committed.
    Committed {
        /// Durable create result.
        result: ConversationReceipt,
    },
    /// The exact command was committed previously.
    Duplicate {
        /// Original durable create result.
        stored_result: ConversationReceipt,
    },
}

/// The result of loading a task run's event stream.
#[derive(Debug, Clone)]
pub struct LoadedStream {
    /// All committed events, ordered by sequence number.
    pub events: Vec<EventEnvelope<TaskRunEvent>>,
    /// The current version of the stream (equals the last event's sequence,
    /// or 0 for an empty stream).
    pub current_version: u64,
    /// The ID of the last event in the stream, or `None` if empty.
    pub last_event_id: Option<EventId>,
}

/// Errors that can occur when reading from the event store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventStoreError {
    /// The aggregate was not found in the store.
    NotFound,
    /// The stored data is corrupt or unreadable.
    CorruptData,
    /// The store is temporarily unavailable.
    Unavailable,
}

// ── UnitOfWork ──────────────────────────────────────────────────────────────

/// Transactional commit boundary with idempotency guard.
pub trait UnitOfWork {
    /// Check whether a command with the given identity has already been
    /// committed.
    ///
    /// Returns a [`ReceiptLookup`]: `Miss`, `Duplicate`, or an error.
    fn lookup_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<ReceiptLookup, CommitError>;

    /// Atomically commit a command's result and its resulting events.
    ///
    /// On success, returns [`CommitResult::Committed`] with the new stream
    /// version. On conflict (version mismatch, idempotency conflict),
    /// returns the appropriate error.
    fn commit(&self, payload: CommandCommit) -> Result<CommitResult, CommitError>;
}

/// Payload for [`UnitOfWork::commit`].
#[derive(Debug, Clone)]
pub struct CommandCommit {
    /// The unique command ID.
    pub command_id: CommandId,
    /// Client-provided idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Scope within which the idempotency key is unique.
    pub idempotency_scope: IdempotencyScope,
    /// Cryptographic fingerprint of the command payload.
    pub command_fingerprint: CommandFingerprint,
    /// The expected version before this commit (for optimistic concurrency).
    pub expected_version: u64,
    /// The events to append.
    pub events: Vec<UncommittedEvent<TaskRunEvent>>,
    /// The command's result, to be stored in the receipt.
    pub command_result: CommandOutcome,
}

/// The result of a receipt lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptLookup {
    /// No matching receipt was found.
    Miss,
    /// An exact match was found; the command was already committed.
    Duplicate {
        /// The stored outcome from the original commit.
        stored_result: CommandOutcome,
    },
}

/// The result of a successful commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitResult {
    /// The commit succeeded.
    Committed {
        /// The new stream version after appending events.
        new_version: u64,
    },
    /// No events were appended — the command was already committed.
    Duplicate {
        /// The stored outcome from the original commit.
        stored_result: CommandOutcome,
    },
}

/// Errors that can occur during commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitError {
    /// Expected stream version does not match the actual version.
    VersionConflict {
        /// The version the caller expected.
        expected: u64,
        /// The actual current version.
        actual: u64,
    },
    /// The version counter would overflow.
    VersionExhausted {
        /// The current version before the commit.
        current: u64,
        /// The number of events attempting to be appended.
        event_count: usize,
    },
    /// A different command was committed with the same idempotency scope/key.
    IdempotencyConflict {
        /// The command ID from the stored receipt.
        stored_command_id: CommandId,
        /// The command ID being attempted now.
        attempted_command_id: CommandId,
        /// The fingerprint from the stored receipt.
        stored_fingerprint: CommandFingerprint,
        /// The fingerprint being attempted now.
        attempted_fingerprint: CommandFingerprint,
    },
    /// A persistent storage failure.
    StorageFailure(StorageFailureKind),
    /// The clock has regressed — timestamps must be monotonically increasing.
    ClockRegression {
        /// The most recent committed timestamp.
        last_timestamp: Timestamp,
        /// The timestamp being attempted now.
        attempted: Timestamp,
    },
    /// The clock could not be read.
    ClockFailure,
    /// Global position counter exhausted.
    GlobalPositionExhausted,
}

/// Closed categories for storage failures — no free strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFailureKind {
    /// Data on disk is corrupt or unreadable.
    CorruptData,
    /// The stored schema version is not supported by this code.
    UnsupportedSchema,
    /// A storage-level integrity check failed.
    IntegrityViolation,
    /// The store is temporarily unavailable.
    Unavailable,
}

// ── IdGenerator ─────────────────────────────────────────────────────────────

/// Generates unique identifiers for aggregates, events, and attempts.
pub trait IdGenerator {
    /// Generate a new unique [`TaskRunId`].
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError>;

    /// Generate a new unique [`ConversationId`].
    fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError>;

    /// Generate a new unique [`AttemptId`].
    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError>;

    /// Generate a new unique loop cycle ID.
    fn next_cycle_id(&self) -> Result<CycleId, IdGenerationError> {
        Err(IdGenerationError::Unavailable)
    }

    /// Generate a new unique loop checkpoint ID.
    fn next_checkpoint_id(&self) -> Result<CheckpointId, IdGenerationError> {
        Err(IdGenerationError::Unavailable)
    }

    /// Generate `count` new unique [`EventId`]s.
    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError>;
}

/// Error from [`IdGenerator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdGenerationError {
    /// The ID source has been exhausted.
    Exhausted,
    /// The ID source is temporarily unavailable.
    Unavailable,
}

// ── Clock ───────────────────────────────────────────────────────────────────

/// Provides the current wall-clock time for event timestamps.
pub trait Clock {
    /// Return the current time as a [`Timestamp`].
    fn now(&self) -> Result<Timestamp, ClockError>;
}

/// Error from [`Clock`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// The clock could not be read.
    Unavailable,
}

/// Provider of authoritative wall-clock microseconds for retry scheduling.
pub trait TimePort {
    fn now_unix_us(&self) -> Result<i64, TimeError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeError {
    Unavailable,
    OutOfRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRetrySchedule {
    pub retry_policy_digest: IntegrityDigest,
    pub budget_reservation_ref: BudgetReservationRef,
    pub delay_ms: u64,
    pub due_at_unix_us: i64,
}

pub trait RetrySchedulePort {
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &self,
        taskrun_id: TaskRunId,
        attempt_id: AttemptId,
        retry_ordinal: u64,
        step_outcome_ref: &StepOutcomeRef,
        requested_policy_digest: &IntegrityDigest,
        requested_budget_reservation: &BudgetReservationRef,
        now_unix_us: i64,
    ) -> Result<PreparedRetrySchedule, RetryScheduleError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryScheduleError {
    Denied,
    BudgetExhausted,
    StaleReservation,
    Unavailable,
}

pub trait WakeEvidenceQueryPort {
    fn validate_current(
        &self,
        evidence: &WakeEvidenceRef,
        taskrun_id: TaskRunId,
        cycle_id: CycleId,
        condition: &WakeCondition,
    ) -> Result<(), WakeEvidenceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeEvidenceError {
    Missing,
    Stale,
    Forged,
    CrossCycle,
    Unavailable,
}

pub trait ReconciliationQueryPort {
    fn validate_current(
        &self,
        evidence: &ReconciliationResultRef,
        taskrun_id: TaskRunId,
        predecessor_attempt_id: AttemptId,
        expected_generation: u64,
        expected_stream_head: u64,
    ) -> Result<(), ReconciliationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationError {
    Missing,
    Stale,
    UnresolvedEffects,
    InvalidBinding,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateEvaluationRef {
    pub gate_id: String,
    pub evidence_digest: IntegrityDigest,
    pub result_digest: IntegrityDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEvaluation {
    pub reference: PlanEvaluationRef,
    pub gate_evaluation_refs: Vec<GateEvaluationRef>,
    pub evaluated_at_unix_us: i64,
    pub superseded_by: Option<PlanEvaluationId>,
}

pub trait VerificationQueryPort {
    fn get_exact(
        &self,
        reference: &PlanEvaluationRef,
    ) -> Result<PlanEvaluation, VerificationQueryError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationQueryError {
    Missing,
    Stale,
    InvalidBinding,
    DigestMismatch,
    Unavailable,
}

// ── Idempotency scope ──────────────────────────────────────────────────────

/// Identifies the runtime authority (the GOCODE host process).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeAuthorityId(pub String);

/// Identifies the principal (user/service) that issued a command.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrincipalId(pub String);

/// Operation tag — a numeric discriminant for each use case.
///
/// Used in idempotency scope and CommandFingerprint canonical encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OperationTag {
    /// Create a new task run.
    CreateTaskRun = 1,
    /// Queue a task run for admission.
    Queue = 2,
    /// Admit a task run for execution.
    Admit = 3,
    /// Start a new execution attempt.
    StartAttempt = 4,
    /// Complete a task run with a terminal result.
    Complete = 5,
    /// Create a new conversation.
    CreateConversation = 6,
    StartLoopCycle = 7,
    CommitContext = 8,
    CommitPlan = 9,
    RecordStepOutcome = 10,
    CompleteLoopCycle = 11,
    CreateNextCycle = 12,
    ScheduleRetry = 13,
    ActivateScheduledRetryAttempt = 14,
    CommitRecoveryResume = 15,
    CommitLoopCheckpoint = 16,
    ResumeLoopWait = 17,
}

/// The aggregate scope within which idempotency is enforced.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AggregateScope {
    /// A task run that does not yet exist (for Create).
    NewTaskRun {
        /// The conversation this task run belongs to.
        conversation_id: ConversationId,
        /// The workspace this task run belongs to.
        workspace_id: WorkspaceId,
    },
    /// An existing task run.
    ExistingTaskRun {
        /// The task run ID.
        taskrun_id: TaskRunId,
    },
    /// A conversation that does not yet exist.
    NewConversation {
        /// Conversation identity selected by the API boundary.
        conversation_id: ConversationId,
        /// Workspace that owns the conversation.
        workspace_id: WorkspaceId,
    },
}

/// Full idempotency scope — runtime, principal, operation, and aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyScope {
    /// The runtime authority that processed the command.
    pub runtime_authority_id: RuntimeAuthorityId,
    /// The principal that issued the command.
    /// Authenticated principal.
    pub principal_id: PrincipalId,
    /// The operation being performed.
    pub operation: OperationTag,
    /// The aggregate scope (new or existing task run).
    pub aggregate_scope: AggregateScope,
}

/// Application command context — identity and metadata carried by every command.
#[derive(Debug, Clone)]
pub struct ApplicationCommandContext {
    /// Unique command identifier.
    pub command_id: gocode_domain::id::CommandId,
    /// Client-supplied idempotency key.
    pub idempotency_key: gocode_domain::id::IdempotencyKey,
    /// Authenticated principal.
    pub principal_id: PrincipalId,
    /// Domain actor for event attribution.
    pub actor: gocode_domain::event::Actor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_tag_discriminants() {
        assert_eq!(OperationTag::CreateTaskRun as u8, 1);
        assert_eq!(OperationTag::Queue as u8, 2);
        assert_eq!(OperationTag::Admit as u8, 3);
        assert_eq!(OperationTag::StartAttempt as u8, 4);
        assert_eq!(OperationTag::Complete as u8, 5);
        assert_eq!(OperationTag::CreateConversation as u8, 6);
        assert_eq!(OperationTag::StartLoopCycle as u8, 7);
        assert_eq!(OperationTag::CommitContext as u8, 8);
        assert_eq!(OperationTag::CommitPlan as u8, 9);
        assert_eq!(OperationTag::RecordStepOutcome as u8, 10);
        assert_eq!(OperationTag::CompleteLoopCycle as u8, 11);
        assert_eq!(OperationTag::CreateNextCycle as u8, 12);
        assert_eq!(OperationTag::ScheduleRetry as u8, 13);
        assert_eq!(OperationTag::ActivateScheduledRetryAttempt as u8, 14);
        assert_eq!(OperationTag::CommitRecoveryResume as u8, 15);
        assert_eq!(OperationTag::CommitLoopCheckpoint as u8, 16);
        assert_eq!(OperationTag::ResumeLoopWait as u8, 17);
    }

    #[test]
    fn test_receipt_lookup_clone_eq() {
        let miss1 = ReceiptLookup::Miss;
        let miss2 = ReceiptLookup::Miss;
        assert_eq!(miss1, miss2);
    }

    #[test]
    fn test_commit_error_clone_eq() {
        let err1 = CommitError::VersionConflict {
            expected: 1,
            actual: 2,
        };
        let err2 = CommitError::VersionConflict {
            expected: 1,
            actual: 2,
        };
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_storage_failure_kind_values() {
        // Ensure all variants are distinguishable
        assert_ne!(
            StorageFailureKind::CorruptData,
            StorageFailureKind::UnsupportedSchema
        );
        assert_ne!(
            StorageFailureKind::IntegrityViolation,
            StorageFailureKind::Unavailable
        );
    }

    #[test]
    fn test_idempotency_scope_clone_eq() {
        let scope1 = IdempotencyScope {
            runtime_authority_id: RuntimeAuthorityId("host-1".into()),
            principal_id: PrincipalId("user-1".into()),
            operation: OperationTag::CreateTaskRun,
            aggregate_scope: AggregateScope::NewTaskRun {
                conversation_id: "018f2e3a-7000-7000-8000-000000000001".parse().unwrap(),
                workspace_id: "018f2e3a-7000-7000-8000-000000000002".parse().unwrap(),
            },
        };
        let scope2 = scope1.clone();
        assert_eq!(scope1, scope2);
    }
}
