//! Domain errors — closed, typed, machine-distinguishable.
//!
//! Every error variant carries the exact data needed for programmatic
//! handling, not just a human-readable message.

use core::fmt;

use crate::event::AggregateType;
use crate::id::{AggregateId, AttemptId, TaskRunId};
use crate::task_run::{TaskRunEventKind, TaskRunState};

// Re-export for convenience — defined in `id.rs`.
pub use crate::id::InvalidIdReason;

/// All domain-level errors produced by the TaskRun aggregate.
///
/// Closed enum — every possible error condition is enumerated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// An event was applied to an aggregate in a state that does not
    /// accept it.
    InvalidTransition {
        /// The state of the aggregate when the event was applied.
        from: TaskRunState,
        /// The event kind that was rejected.
        event: TaskRunEventKind,
    },

    /// An attempt was made to apply an event to a terminal aggregate.
    TerminalImmutable {
        /// The terminal state of the aggregate.
        current: TaskRunState,
    },

    /// An identifier failed validation.
    InvalidId {
        /// The entity whose ID was rejected (e.g., "TaskRunId").
        entity: &'static str,
        /// The reason for rejection.
        reason: InvalidIdReason,
    },

    /// The `aggregate_id` in an event does not match the expected value.
    AggregateIdMismatch {
        /// The expected aggregate ID.
        expected: AggregateId,
        /// The actual aggregate ID from the event.
        actual: AggregateId,
    },

    /// Replay was attempted on an event stream that does not contain
    /// a creation event.
    MissingCreationEvent {
        /// The type of aggregate expected.
        aggregate_type: AggregateType,
    },

    /// A creation event appeared more than once in the same event stream.
    DuplicateCreationEvent {
        /// The type of aggregate.
        aggregate_type: AggregateType,
        /// The aggregate ID that was duplicated.
        aggregate_id: AggregateId,
    },

    /// An [`AttemptId`] was reused — every attempt must have a unique ID.
    DuplicateAttemptId {
        /// The owning task run.
        taskrun_id: TaskRunId,
        /// The duplicate attempt ID.
        attempt_id: AttemptId,
    },

    /// The sequence number in the event stream is not continuous.
    SequenceGap {
        /// The expected (next) sequence number.
        expected: u64,
        /// The actual sequence number from the event.
        actual: u64,
    },

    /// The initial sequence number in an event stream is not 1.
    InvalidInitialSequence {
        /// Expected initial sequence (1).
        expected: u64,
        /// Actual first sequence number.
        actual: u64,
    },
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, event } => {
                write!(
                    f,
                    "invalid transition: cannot apply {:?} in state {:?}",
                    event, from
                )
            }
            Self::TerminalImmutable { current } => {
                write!(
                    f,
                    "aggregate is in terminal state {:?} and cannot be modified",
                    current
                )
            }
            Self::InvalidId { entity, reason } => {
                write!(f, "invalid ID for {}: {}", entity, reason)
            }
            Self::AggregateIdMismatch { expected, actual } => {
                write!(
                    f,
                    "aggregate ID mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Self::MissingCreationEvent { aggregate_type } => {
                write!(
                    f,
                    "missing creation event for aggregate type {}",
                    aggregate_type
                )
            }
            Self::DuplicateCreationEvent {
                aggregate_type,
                aggregate_id,
            } => {
                write!(
                    f,
                    "duplicate creation event for {} aggregate {}",
                    aggregate_type, aggregate_id
                )
            }
            Self::DuplicateAttemptId {
                taskrun_id,
                attempt_id,
            } => {
                write!(
                    f,
                    "duplicate attempt ID {} for task run {}",
                    attempt_id, taskrun_id
                )
            }
            Self::SequenceGap { expected, actual } => {
                write!(f, "sequence gap: expected {}, got {}", expected, actual)
            }
            Self::InvalidInitialSequence { expected, actual } => {
                write!(
                    f,
                    "invalid initial sequence: expected {}, got {}",
                    expected, actual
                )
            }
        }
    }
}

impl std::error::Error for DomainError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";
    #[allow(dead_code)]
    const ID2: &str = "018f2e3a-7000-7000-8000-000000000001";

    #[test]
    fn test_domain_error_is_error_trait() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<DomainError>();
    }

    #[test]
    fn test_domain_error_display_invalid_transition() {
        let err = DomainError::InvalidTransition {
            from: TaskRunState::Created,
            event: TaskRunEventKind::AttemptStarted,
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid transition"));
        assert!(msg.contains("Created"));
        assert!(msg.contains("AttemptStarted"));
    }

    #[test]
    fn test_domain_error_display_terminal_immutable() {
        let err = DomainError::TerminalImmutable {
            current: TaskRunState::Succeeded,
        };
        assert!(err.to_string().contains("terminal"));
    }

    #[test]
    fn test_domain_error_display_sequence_gap() {
        let err = DomainError::SequenceGap {
            expected: 5,
            actual: 7,
        };
        let msg = err.to_string();
        assert!(msg.contains("5"));
        assert!(msg.contains("7"));
    }

    #[test]
    fn test_domain_error_debug() {
        let err = DomainError::InvalidInitialSequence {
            expected: 1,
            actual: 0,
        };
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("InvalidInitialSequence"));
    }
}
