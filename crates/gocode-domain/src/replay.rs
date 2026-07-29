//! Replay domain types — cursor, scope, and delivered event.
//!
//! Per ADR-0013: transport-neutral cursor-based durable replay.

use sha2::{Digest, Sha256};

use crate::event::{EventEnvelope, Sensitivity};
use crate::id::{AggregateId, EventId, EventLogLineageId, IntegrityDigest};

/// Current cursor schema version.
pub const CURSOR_SCHEMA_VERSION: u32 = 1;

/// Replay scope — a closed tagged selector for event streams.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ReplayScope {
    /// An aggregate scope: aggregateType + aggregateID.
    Aggregate {
        aggregate_type: u8,
        aggregate_id: [u8; 16],
    },
    /// A TaskRun feed scope.
    TaskRunFeed { taskrun_id: [u8; 16] },
    /// An audit feed scope (requires distinct audit-read capability).
    AuditFeed {
        authority_id: [u8; 16],
        scope_id: [u8; 16],
    },
}

impl ReplayScope {
    /// Compute the canonical scope digest (SHA-256 over versioned representation).
    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(1u32.to_be_bytes());
        match self {
            Self::Aggregate {
                aggregate_type,
                aggregate_id,
            } => {
                hasher.update([0u8]);
                hasher.update([*aggregate_type]);
                hasher.update(aggregate_id);
            }
            Self::TaskRunFeed { taskrun_id } => {
                hasher.update([1u8]);
                hasher.update(taskrun_id);
            }
            Self::AuditFeed {
                authority_id,
                scope_id,
            } => {
                hasher.update([2u8]);
                hasher.update(authority_id);
                hasher.update(scope_id);
            }
        }
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }
}

/// Errors when building or validating a ReplayCursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorError {
    InvalidIntegrity,
    WrongSchema,
    WrongLineage,
    WrongScope,
    UnknownEvent,
    PositionOutOfRange,
}

/// An opaque, integrity-protected replay cursor.
///
/// Per ADR-0013: binds cursorSchemaVersion, EventLogLineageID,
/// ReplayScope digest, inclusive LogPosition, event identity,
/// and integrity evidence. Not an authorization token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplayCursor {
    /// The event this cursor points to.
    pub event_id: EventId,
    /// The aggregate this event belongs to.
    pub aggregate_id: AggregateId,
    /// Aggregate-local sequence number (monotonic, starts at 1).
    pub sequence: u64,
    /// Global position in the event log (monotonic, append-only).
    pub global_position: i64,
    /// The log lineage that issued this cursor.
    pub lineage_id: EventLogLineageId,
    /// The scope this cursor is valid for.
    pub scope: ReplayScope,
    /// Schema version of this cursor.
    pub schema_version: u32,
    /// Sensitivity of the event at this cursor.
    pub sensitivity: Sensitivity,
    /// Canonical event type string.
    pub event_type: String,
    /// Integrity evidence (HMAC-SHA256 over cursor fields + server secret).
    pub integrity: IntegrityDigest,
}

/// A delivered event paired with its ackable cursor.
#[derive(Debug, Clone)]
pub struct DeliveredEvent<E> {
    /// The canonical committed event.
    pub event: EventEnvelope<E>,
    /// The ackable cursor for this event.
    pub cursor: ReplayCursor,
}

/// Catch-up completion proof — server-issued, session-bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchUpCompletion {
    /// Session ID this proof belongs to.
    pub session_id: [u8; 16],
    /// High-water reference captured at session open.
    pub high_water_ref: Vec<u8>,
    /// The last acknowledged cursor (None for empty catch-up).
    pub last_ack_cursor: Option<ReplayCursor>,
    /// Integrity evidence.
    pub proof: IntegrityDigest,
}

/// Live delivery identifier — opaque, session-bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveDeliveryId {
    pub id: [u8; 16],
}

/// A page of delivered events with an optional continuation cursor.
#[derive(Debug, Clone)]
pub struct ReplayPage<E> {
    /// Ordered delivered events with their cursors.
    pub events: Vec<DeliveredEvent<E>>,
    /// Whether there are more events to read (for pagination).
    pub has_more: bool,
    /// The next unread continuation (navigation token, NOT ackable).
    pub continuation: Option<ReplayCursor>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_scope_canonical_digest_deterministic() {
        let scope = ReplayScope::Aggregate {
            aggregate_type: 1,
            aggregate_id: [2; 16],
        };

        assert_eq!(scope.canonical_digest(), scope.canonical_digest());
    }

    #[test]
    fn test_replay_scope_canonical_digest_differs() {
        let aggregate = ReplayScope::Aggregate {
            aggregate_type: 1,
            aggregate_id: [2; 16],
        };
        let taskrun_feed = ReplayScope::TaskRunFeed {
            taskrun_id: [2; 16],
        };

        assert_ne!(
            aggregate.canonical_digest(),
            taskrun_feed.canonical_digest()
        );
    }

    #[test]
    fn test_cursor_schema_version_is_positive() {
        const {
            assert!(CURSOR_SCHEMA_VERSION > 0);
        };
    }
}
