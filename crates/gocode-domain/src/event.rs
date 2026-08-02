//! Three-stage domain event model: draft → uncommitted → envelope.
//!
//! ```text
//! Domain decide  → DomainEventDraft<E>
//! Application     → UncommittedEvent<E>  (+ EventId, CommandContext, causation_id)
//! Persistence     → EventEnvelope<E>     (+ sequence, timestamp, integrity_digest)
//! ```

use core::fmt;

use crate::id::{
    AggregateId, CommandId, EventId, IdempotencyKey, IntegrityDigest, InvalidIdReason,
    MAX_ACTOR_BYTES, MAX_EVENT_TYPE_BYTES,
};
use crate::timestamp::Timestamp;
include!("event/classification.rs");
include!("event/draft.rs");
include!("event/envelope.rs");
include!("event/materialize.rs");

#[cfg(test)]
mod tests {
    include!("event/tests.rs");
}
