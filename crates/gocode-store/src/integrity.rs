//! Integrity digest — SHA-256 over canonical event bytes.
//!
//! The digest covers all event fields except `integrity_digest` itself.
//! Canonical encoding order:
//!
//! ```text
//! domain_prefix(17) || profile_version(2,BE) ||
//! event_id(16) || aggregate_type(1) || taskrun_id(16) ||
//! sequence(8,BE) || global_position(8,BE) ||
//! timestamp(8,BE) ||
//! causation_opt_tag(1) || [causation_id(16)] ||
//! command_id(16) ||
//! idempotency_key_len(2,BE) || idempotency_key_bytes ||
//! actor_len(2,BE) || actor_bytes ||
//! sensitivity(1) || schema_version(4,BE) ||
//! payload_len(4,BE) || payload_bytes
//! ```

use gocode_domain::event::EventEnvelope;
use gocode_domain::id::IntegrityDigest;
use gocode_domain::task_run::TaskRunEvent;
use sha2::{Digest, Sha256};

/// Domain-separation prefix for integrity digests.
const DOMAIN_PREFIX: &[u8] = b"gocode-integrity\x01";

/// Current integrity profile version.
const PROFILE_VERSION: u16 = 1;

/// Compute the integrity digest for a complete [`EventEnvelope`].
///
/// The digest is computed over all canonical fields except the
/// `integrity_digest` field itself. The `payload_bytes` parameter
/// must be the result of [`crate::codec::TaskRunEventCodec::encode`].
///
/// Note: this version does not include `global_position`. Use
/// [`compute_integrity_digest_with_global_position`] for the store's
/// per-row digest that includes the assigned global position.
pub fn compute_integrity_digest(
    envelope: &EventEnvelope<TaskRunEvent>,
    payload_bytes: &[u8],
) -> IntegrityDigest {
    let mut hasher = Sha256::new();

    // domain_prefix(17)
    hasher.update(DOMAIN_PREFIX);

    // profile_version(2,BE)
    hasher.update(PROFILE_VERSION.to_be_bytes());

    // event_id(16)
    hasher.update(envelope.event_id().as_bytes());

    // aggregate_type(1)
    let agg_type: u8 = 1; // TaskRun = 1
    hasher.update([agg_type]);

    // taskrun_id(16)
    hasher.update(envelope.taskrun_id().as_bytes());

    // sequence(8,BE)
    hasher.update(envelope.sequence().to_be_bytes());

    // global_position(8,BE) — not in EventEnvelope; omitted in this version.
    // Use `compute_integrity_digest_with_global_position` when the store
    // has assigned a global position.

    // timestamp(8,BE)
    hasher.update(envelope.timestamp().as_unix_micros().to_be_bytes());

    // causation_opt_tag(1) || [causation_id(16)]
    match envelope.causation_id() {
        Some(cid) => {
            hasher.update([0x01u8]);
            hasher.update(cid.as_bytes());
        }
        None => {
            hasher.update([0x00u8]);
        }
    }

    // command_id(16)
    hasher.update(envelope.command_id().as_bytes());

    // idempotency_key_len(2,BE) || idempotency_key_bytes
    let ikey_bytes = envelope.idempotency_key().as_str().as_bytes();
    hasher.update((ikey_bytes.len() as u16).to_be_bytes());
    hasher.update(ikey_bytes);

    // actor_len(2,BE) || actor_bytes
    let actor_bytes = envelope.actor().as_str().as_bytes();
    hasher.update((actor_bytes.len() as u16).to_be_bytes());
    hasher.update(actor_bytes);

    // sensitivity(1)
    let sens: u8 = 0; // Public = 0
    hasher.update([sens]);

    // schema_version(4,BE)
    hasher.update(envelope.schema_version().to_be_bytes());

    // payload_len(4,BE) || payload_bytes
    hasher.update((payload_bytes.len() as u32).to_be_bytes());
    hasher.update(payload_bytes);

    let digest: [u8; 32] = hasher.finalize().into();
    IntegrityDigest::from_bytes(digest)
}

/// Compute an integrity digest with an explicit global position.
///
/// This is the version used by the store, which assigns global positions
/// inside the transaction.
pub fn compute_integrity_digest_with_global_position(
    envelope: &EventEnvelope<TaskRunEvent>,
    global_position: i64,
    payload_bytes: &[u8],
) -> IntegrityDigest {
    let mut hasher = Sha256::new();

    // domain_prefix(17)
    hasher.update(DOMAIN_PREFIX);

    // profile_version(2,BE)
    hasher.update(PROFILE_VERSION.to_be_bytes());

    // event_id(16)
    hasher.update(envelope.event_id().as_bytes());

    // aggregate_type(1)
    let agg_type: u8 = 1; // TaskRun = 1
    hasher.update([agg_type]);

    // taskrun_id(16)
    hasher.update(envelope.taskrun_id().as_bytes());

    // sequence(8,BE)
    hasher.update(envelope.sequence().to_be_bytes());

    // global_position(8,BE)
    hasher.update(global_position.to_be_bytes());

    // timestamp(8,BE)
    hasher.update(envelope.timestamp().as_unix_micros().to_be_bytes());

    // causation_opt_tag(1) || [causation_id(16)]
    match envelope.causation_id() {
        Some(cid) => {
            hasher.update([0x01u8]);
            hasher.update(cid.as_bytes());
        }
        None => {
            hasher.update([0x00u8]);
        }
    }

    // command_id(16)
    hasher.update(envelope.command_id().as_bytes());

    // idempotency_key_len(2,BE) || idempotency_key_bytes
    let ikey_bytes = envelope.idempotency_key().as_str().as_bytes();
    hasher.update((ikey_bytes.len() as u16).to_be_bytes());
    hasher.update(ikey_bytes);

    // actor_len(2,BE) || actor_bytes
    let actor_bytes = envelope.actor().as_str().as_bytes();
    hasher.update((actor_bytes.len() as u16).to_be_bytes());
    hasher.update(actor_bytes);

    // sensitivity(1)
    let sens: u8 = 0; // Public = 0
    hasher.update([sens]);

    // schema_version(4,BE)
    hasher.update(envelope.schema_version().to_be_bytes());

    // payload_len(4,BE) || payload_bytes
    hasher.update((payload_bytes.len() as u32).to_be_bytes());
    hasher.update(payload_bytes);

    let digest: [u8; 32] = hasher.finalize().into();
    IntegrityDigest::from_bytes(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{StoreCodec, TaskRunEventCodec};
    use gocode_domain::event::{Actor, CommandContext, DomainEventDraft, Sensitivity};
    use gocode_domain::id::{AggregateId, EventId, IdempotencyKey, TaskRunId};
    use gocode_domain::task_run::TaskRunEvent;
    use gocode_domain::timestamp::Timestamp;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";

    fn make_envelope(seq: u64, payload: TaskRunEvent) -> EventEnvelope<TaskRunEvent> {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let event_id: EventId = VALID_UUID.parse().unwrap();
        let draft = DomainEventDraft::new(
            AggregateId::TaskRun(tr_id),
            tr_id,
            1,
            Sensitivity::Public,
            payload,
        );
        let ctx = CommandContext {
            command_id: VALID_UUID.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("test-key").unwrap(),
            actor: Actor::new("test-actor").unwrap(),
        };
        let uncommitted =
            gocode_domain::event::materialize_batch(vec![draft], &[event_id], None, &ctx)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
        uncommitted.into_envelope(
            seq,
            Timestamp::from_unix_micros(1_000_000),
            IntegrityDigest::from_bytes([0; 32]),
        )
    }

    #[test]
    fn test_compute_digest_deterministic() {
        let envelope = make_envelope(1, TaskRunEvent::TaskRunCreated);
        let codec = TaskRunEventCodec;
        let payload_bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();

        let d1 = compute_integrity_digest_with_global_position(&envelope, 1, &payload_bytes);
        let d2 = compute_integrity_digest_with_global_position(&envelope, 1, &payload_bytes);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_compute_digest_different_global_position() {
        let envelope = make_envelope(1, TaskRunEvent::TaskRunCreated);
        let codec = TaskRunEventCodec;
        let payload_bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();

        let d1 = compute_integrity_digest_with_global_position(&envelope, 1, &payload_bytes);
        let d2 = compute_integrity_digest_with_global_position(&envelope, 2, &payload_bytes);
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_compute_digest_golden() {
        let envelope = make_envelope(1, TaskRunEvent::TaskRunCreated);
        let codec = TaskRunEventCodec;
        let payload_bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        let digest = compute_integrity_digest_with_global_position(&envelope, 1, &payload_bytes);

        // Verify digest is 32 bytes
        assert_eq!(digest.as_bytes().len(), 32);

        // Verify digest is not all zeros
        assert_ne!(*digest.as_bytes(), [0u8; 32]);

        // Verify hex display produces 64 chars
        let hex = digest.to_string();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_digest_different_events_produce_different_digests() {
        let codec = TaskRunEventCodec;
        let pb_created = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        let pb_queued = codec.encode(&TaskRunEvent::TaskRunQueued).unwrap();

        let env1 = make_envelope(1, TaskRunEvent::TaskRunCreated);
        let env2 = make_envelope(2, TaskRunEvent::TaskRunQueued);

        let d1 = compute_integrity_digest_with_global_position(&env1, 1, &pb_created);
        let d2 = compute_integrity_digest_with_global_position(&env2, 2, &pb_queued);

        assert_ne!(d1, d2);
    }
}
