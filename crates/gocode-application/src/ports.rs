//! Application ports — abstract traits for persistence, identity, and time.
//!
//! All ports are trait-only; no concrete adapters in this crate.

use gocode_domain::event::{EventEnvelope, UncommittedEvent};
use gocode_domain::id::{
    AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, TaskRunId, WorkspaceId,
};
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;

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

    /// Generate a new unique [`AttemptId`].
    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError>;

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
