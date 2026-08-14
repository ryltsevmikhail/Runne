//! Shared replay-safe references used by durable Agent Loop events.

use crate::id::{
    AttemptId, BudgetReservationId, CheckpointId, IntegrityDigest, ResultId, TaskRunId,
};

const MAX_MEDIA_TYPE_BYTES: usize = 255;

/// Immutable reference to a content-addressed result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultRef {
    /// Durable result identity.
    result_id: ResultId,
    /// Bounded media type describing the referenced representation.
    media_type: String,
    /// Digest of the immutable result bytes.
    integrity_digest: IntegrityDigest,
}

impl ResultRef {
    /// Construct a validated result reference.
    pub fn new(
        result_id: ResultId,
        media_type: impl Into<String>,
        integrity_digest: IntegrityDigest,
    ) -> Result<Self, ReferenceError> {
        let media_type = media_type.into();
        let len = media_type.len();
        if media_type.is_empty() {
            return Err(ReferenceError::EmptyMediaType);
        }
        if len > MAX_MEDIA_TYPE_BYTES {
            return Err(ReferenceError::MediaTypeTooLong {
                max: MAX_MEDIA_TYPE_BYTES,
                actual: len,
            });
        }
        if media_type
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control())
        {
            return Err(ReferenceError::InvalidMediaType);
        }
        Ok(Self {
            result_id,
            media_type,
            integrity_digest,
        })
    }

    /// Returns the durable result identity.
    pub const fn result_id(&self) -> &ResultId {
        &self.result_id
    }

    /// Returns the validated media type.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Returns the immutable result digest.
    pub const fn integrity_digest(&self) -> &IntegrityDigest {
        &self.integrity_digest
    }
}

/// Replay-safe reference to a retry budget reservation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BudgetReservationRef {
    /// Reservation identity.
    pub reservation_id: BudgetReservationId,
    /// Owning task run.
    pub taskrun_id: TaskRunId,
    /// Attempt against which the reservation was issued.
    pub attempt_id: AttemptId,
    /// Retry ordinal authorized by the reservation.
    pub retry_ordinal: u64,
    /// Digest of the immutable reservation record.
    pub reservation_digest: IntegrityDigest,
}

/// Replay-safe reference to a committed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRef {
    /// Checkpoint identity.
    pub checkpoint_id: CheckpointId,
    /// Stream position represented by the checkpoint.
    pub event_position: u64,
    /// Digest of the checkpoint body.
    pub integrity_digest: IntegrityDigest,
}

/// Validation errors for shared references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceError {
    /// Media type must not be empty.
    EmptyMediaType,
    /// Media type exceeds its byte bound.
    MediaTypeTooLong {
        /// Maximum accepted byte length.
        max: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// Media type contains an ASCII control byte.
    InvalidMediaType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::IntegrityDigest;

    const UUID: &str = "018f2e3a-7000-7000-8000-000000000010";

    #[test]
    fn result_ref_rejects_empty_media_type() {
        let result_id: ResultId = UUID.parse().unwrap();
        assert!(ResultRef::new(result_id, "", IntegrityDigest::from_bytes([7; 32])).is_err());
    }

    #[test]
    fn result_ref_enforces_exact_media_type_bound_and_control_exclusion() {
        let result_id: ResultId = UUID.parse().unwrap();
        let digest = IntegrityDigest::from_bytes([7; 32]);
        assert!(ResultRef::new(result_id, "a".repeat(255), digest).is_ok());
        for media_type in [String::new(), "a\njson".into(), "a".repeat(256)] {
            assert!(ResultRef::new(result_id, media_type, digest).is_err());
        }
    }

    #[test]
    fn budget_reservation_ref_binds_retry_scope() {
        let reference = BudgetReservationRef {
            reservation_id: UUID.parse::<BudgetReservationId>().unwrap(),
            taskrun_id: UUID.parse::<TaskRunId>().unwrap(),
            attempt_id: UUID.parse::<AttemptId>().unwrap(),
            retry_ordinal: 2,
            reservation_digest: IntegrityDigest::from_bytes([3; 32]),
        };
        assert_eq!(reference.retry_ordinal, 2);
    }

    #[test]
    fn checkpoint_ref_preserves_position_and_digest() {
        let reference = CheckpointRef {
            checkpoint_id: UUID.parse::<CheckpointId>().unwrap(),
            event_position: 42,
            integrity_digest: IntegrityDigest::from_bytes([9; 32]),
        };
        assert_eq!(reference.event_position, 42);
    }
}
