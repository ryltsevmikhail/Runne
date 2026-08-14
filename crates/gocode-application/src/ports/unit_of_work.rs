// ── UnitOfWork ──────────────────────────────────────────────────────────────

/// Transactional commit boundary with idempotency guard.
pub trait UnitOfWork {
    /// Check whether a command with the given identity has already been
    /// committed.
    ///
    /// `Duplicate` requires an exact match of command ID, scope,
    /// idempotency key, and semantic fingerprint. Any changed identity field
    /// is an idempotency conflict.
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
    /// The same exact identity rule is rechecked inside the writer
    /// transaction so a concurrent preflight miss cannot replay a different
    /// command. On success, returns [`CommitResult::Committed`] with the new
    /// stream version. On conflict, returns the appropriate error.
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
    /// Prohibited content or unavailable policy classification denied mutation.
    PolicyDenied,
    /// Data on disk is corrupt or unreadable.
    CorruptData,
    /// The stored schema version is not supported by this code.
    UnsupportedSchema,
    /// A storage-level integrity check failed.
    IntegrityViolation,
    /// The store is temporarily unavailable.
    Unavailable,
}
