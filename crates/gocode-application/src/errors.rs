//! Application errors — closed, typed, machine-distinguishable.
//!
//! Every error variant carries the exact data needed for programmatic
//! handling, not just a human-readable message.

use core::fmt;

use gocode_domain::error::DomainError;
use gocode_domain::id::{CommandId, TaskRunId};

use crate::fingerprint::CommandFingerprint;
use crate::ports::CommitError;
pub use crate::ports::{
    ClockError, CommitError as CommitErrorType, EventStoreError, IdGenerationError,
    ReconciliationError, RetryScheduleError, StorageFailureKind, TimeError, VerificationQueryError,
    WakeEvidenceError,
};

/// Typed stream consistency violations.
///
/// These indicate a mismatch between what the application layer expects
/// and what the store returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamConsistencyViolation {
    /// The stream has version > 0 but no events.
    EmptyWithNonZeroVersion {
        /// The version that was returned with no events.
        current_version: u64,
    },
    /// The stream has events but version == 0.
    NonEmptyWithZeroVersion,
    /// The stream has events but no `last_event_id`.
    NonEmptyWithMissingLastId,
    /// An event's sequence number does not match what was expected.
    SequenceMismatch {
        /// The index (0-based) of the event in the returned slice.
        index: usize,
        /// The expected sequence number.
        expected: u64,
        /// The actual sequence number.
        actual: u64,
    },
    /// The last event's ID does not match `last_event_id`.
    LastEventIdMismatch,
}

/// Fingerprint computation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintError {
    /// The terminal reason string exceeds the maximum allowed length.
    TerminalReasonTooLong {
        /// The maximum allowed bytes.
        max: usize,
        /// The actual byte length.
        actual: usize,
    },
}

/// All application-level errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationError {
    /// A domain rule was violated (invalid transition, duplicate IDs, etc.).
    Domain(DomainError),
    /// Optimistic concurrency control: expected version does not match.
    VersionConflict {
        /// The version the caller expected.
        expected: u64,
        /// The actual version in the store.
        actual: u64,
    },
    /// The stream version would overflow.
    VersionExhausted {
        /// The current version before the commit.
        current: u64,
        /// The number of events attempting to be appended.
        event_count: usize,
    },
    /// A different command already used the same idempotency scope/key.
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
    /// The ID generator failed.
    IdGenerationFailed(IdGenerationError),
    /// The command fingerprint could not be computed.
    InvalidCommandFingerprint(FingerprintError),
    /// The event store could not be read.
    EventStoreFailed(EventStoreError),
    /// A persistent storage failure occurred.
    StorageFailed(StorageFailureKind),
    /// The aggregate was not found in the store.
    AggregateNotFound {
        /// The task run ID that was not found.
        taskrun_id: TaskRunId,
    },
    /// A stream consistency violation was detected.
    StreamConsistencyViolation(StreamConsistencyViolation),
    /// The commit returned a version that does not match the computed version.
    CommitVersionMismatch {
        /// The version computed by the pipeline.
        computed: u64,
        /// The version returned by the commit.
        returned: u64,
    },
    TimePortFailed(TimeError),
    RetryScheduleRejected(RetryScheduleError),
    WakeEvidenceRejected(WakeEvidenceError),
    ReconciliationRejected(ReconciliationError),
    VerificationRejected(VerificationQueryError),
    InvalidAuthorityResult,
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(e) => write!(f, "domain error: {}", e),
            Self::VersionConflict { expected, actual } => {
                write!(
                    f,
                    "version conflict: expected {}, actual {}",
                    expected, actual
                )
            }
            Self::VersionExhausted {
                current,
                event_count,
            } => {
                write!(
                    f,
                    "version exhausted: current={}, event_count={}",
                    current, event_count
                )
            }
            Self::IdempotencyConflict {
                stored_command_id,
                attempted_command_id,
                ..
            } => {
                write!(
                    f,
                    "idempotency conflict: stored command {} conflicts with attempted {}",
                    stored_command_id, attempted_command_id
                )
            }
            Self::IdGenerationFailed(e) => {
                write!(f, "ID generation failed: {:?}", e)
            }
            Self::InvalidCommandFingerprint(e) => {
                write!(f, "invalid command fingerprint: {:?}", e)
            }
            Self::EventStoreFailed(e) => {
                write!(f, "event store failed: {:?}", e)
            }
            Self::StorageFailed(kind) => {
                write!(f, "storage failure: {:?}", kind)
            }
            Self::AggregateNotFound { taskrun_id } => {
                write!(f, "aggregate not found: {}", taskrun_id)
            }
            Self::StreamConsistencyViolation(v) => {
                write!(f, "stream consistency violation: {:?}", v)
            }
            Self::CommitVersionMismatch { computed, returned } => {
                write!(
                    f,
                    "commit version mismatch: computed {}, returned {}",
                    computed, returned
                )
            }
            Self::TimePortFailed(error) => write!(f, "time port failed: {:?}", error),
            Self::RetryScheduleRejected(error) => {
                write!(f, "retry schedule rejected: {:?}", error)
            }
            Self::WakeEvidenceRejected(error) => {
                write!(f, "wake evidence rejected: {:?}", error)
            }
            Self::ReconciliationRejected(error) => {
                write!(f, "reconciliation rejected: {:?}", error)
            }
            Self::VerificationRejected(error) => {
                write!(f, "verification rejected: {:?}", error)
            }
            Self::InvalidAuthorityResult => write!(f, "authority returned inconsistent data"),
        }
    }
}

impl std::error::Error for ApplicationError {}

impl From<DomainError> for ApplicationError {
    fn from(e: DomainError) -> Self {
        Self::Domain(e)
    }
}

impl From<CommitError> for ApplicationError {
    fn from(e: CommitError) -> Self {
        match e {
            CommitError::VersionConflict { expected, actual } => {
                Self::VersionConflict { expected, actual }
            }
            CommitError::VersionExhausted {
                current,
                event_count,
            } => Self::VersionExhausted {
                current,
                event_count,
            },
            CommitError::IdempotencyConflict {
                stored_command_id,
                attempted_command_id,
                stored_fingerprint,
                attempted_fingerprint,
            } => Self::IdempotencyConflict {
                stored_command_id,
                attempted_command_id,
                stored_fingerprint,
                attempted_fingerprint,
            },
            CommitError::StorageFailure(kind) => Self::StorageFailed(kind),
            CommitError::ClockRegression { .. } => {
                Self::StorageFailed(StorageFailureKind::IntegrityViolation)
            }
            CommitError::ClockFailure => Self::StorageFailed(StorageFailureKind::Unavailable),
            CommitError::GlobalPositionExhausted => {
                Self::StorageFailed(StorageFailureKind::IntegrityViolation)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";

    #[test]
    fn test_application_error_is_error_trait() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<ApplicationError>();
    }

    #[test]
    fn test_stream_consistency_violation_clone_eq() {
        let v1 = StreamConsistencyViolation::EmptyWithNonZeroVersion { current_version: 5 };
        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_fingerprint_error_clone_eq() {
        let e1 = FingerprintError::TerminalReasonTooLong {
            max: 4096,
            actual: 5000,
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_domain_error_conversion() {
        let domain_err = DomainError::TerminalImmutable {
            current: gocode_domain::task_run::TaskRunState::Succeeded,
        };
        let app_err: ApplicationError = domain_err.into();
        assert!(matches!(app_err, ApplicationError::Domain(_)));
    }

    #[test]
    fn test_commit_error_conversion_version_conflict() {
        let commit_err = CommitError::VersionConflict {
            expected: 1,
            actual: 3,
        };
        let app_err: ApplicationError = commit_err.into();
        assert!(matches!(
            app_err,
            ApplicationError::VersionConflict {
                expected: 1,
                actual: 3
            }
        ));
    }

    #[test]
    fn test_application_error_display() {
        let err = ApplicationError::AggregateNotFound {
            taskrun_id: VALID_UUID.parse().unwrap(),
        };
        let msg = err.to_string();
        assert!(msg.contains("aggregate not found"));
    }
}
