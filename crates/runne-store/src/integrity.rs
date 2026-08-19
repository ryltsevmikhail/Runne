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

use runne_domain::event::EventEnvelope;
use runne_domain::id::{AggregateId, IntegrityDigest, TaskRunId};
use runne_domain::task_run::TaskRunEvent;
use sha2::{Digest, Sha256};

/// Domain-separation prefix for integrity digests.
const DOMAIN_PREFIX: &[u8] = b"runne-integrity\x01";

/// Current integrity profile version.
const PROFILE_VERSION: u16 = 1;

/// Integrity computation rejected an event that is not correlated to a TaskRun.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    /// TaskRun event streams require a TaskRun correlation aggregate.
    NonTaskRunCorrelation(AggregateId),
    /// The integrity profile does not define the supplied aggregate kind.
    UnsupportedAggregate(AggregateId),
}

fn taskrun_correlation_id(
    envelope: &EventEnvelope<TaskRunEvent>,
) -> Result<&TaskRunId, IntegrityError> {
    match envelope.correlation_id() {
        AggregateId::TaskRun(taskrun_id) => Ok(taskrun_id),
        correlation_id => Err(IntegrityError::NonTaskRunCorrelation(
            correlation_id.clone(),
        )),
    }
}

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
) -> Result<IntegrityDigest, IntegrityError> {
    let taskrun_id = taskrun_correlation_id(envelope)?;
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
    hasher.update(taskrun_id.as_bytes());

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
    Ok(IntegrityDigest::from_bytes(digest))
}

/// Compute an integrity digest with an explicit global position.
///
/// This is the version used by the store, which assigns global positions
/// inside the transaction.
pub fn compute_integrity_digest_with_global_position(
    envelope: &EventEnvelope<TaskRunEvent>,
    global_position: i64,
    payload_bytes: &[u8],
) -> Result<IntegrityDigest, IntegrityError> {
    let taskrun_id = taskrun_correlation_id(envelope)?;
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
    hasher.update(taskrun_id.as_bytes());

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
    Ok(IntegrityDigest::from_bytes(digest))
}

/// Computes the typed-aggregate integrity profile used for new Phase 2b rows.
///
/// Profile 2 includes both aggregate and correlation discriminants and IDs.
/// Existing profile-1 TaskRun rows retain their original bytes and digest.
pub fn compute_integrity_digest_v2_with_global_position<E>(
    envelope: &EventEnvelope<E>,
    global_position: i64,
    payload_bytes: &[u8],
) -> Result<IntegrityDigest, IntegrityError> {
    let (aggregate_type, aggregate_id) = typed_aggregate(envelope.aggregate_id())?;
    let (correlation_type, correlation_id) = typed_aggregate(envelope.correlation_id())?;
    let mut hasher = Sha256::new();

    hasher.update(DOMAIN_PREFIX);
    hasher.update(2_u16.to_be_bytes());
    hasher.update(envelope.event_id().as_bytes());
    hasher.update([aggregate_type]);
    hasher.update(aggregate_id);
    hasher.update([correlation_type]);
    hasher.update(correlation_id);
    hasher.update(envelope.sequence().to_be_bytes());
    hasher.update(global_position.to_be_bytes());
    hasher.update(envelope.timestamp().as_unix_micros().to_be_bytes());
    match envelope.causation_id() {
        Some(causation_id) => {
            hasher.update([1]);
            hasher.update(causation_id.as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(envelope.command_id().as_bytes());
    let idempotency_key = envelope.idempotency_key().as_str().as_bytes();
    hasher.update((idempotency_key.len() as u16).to_be_bytes());
    hasher.update(idempotency_key);
    let actor = envelope.actor().as_str().as_bytes();
    hasher.update((actor.len() as u16).to_be_bytes());
    hasher.update(actor);
    let sensitivity = match envelope.sensitivity() {
        runne_domain::event::Sensitivity::Public => 0,
        runne_domain::event::Sensitivity::Internal => 1,
        runne_domain::event::Sensitivity::Sensitive => 2,
    };
    hasher.update([sensitivity]);
    hasher.update(envelope.schema_version().to_be_bytes());
    hasher.update((payload_bytes.len() as u32).to_be_bytes());
    hasher.update(payload_bytes);

    Ok(IntegrityDigest::from_bytes(hasher.finalize().into()))
}

fn typed_aggregate(aggregate_id: &AggregateId) -> Result<(u8, &[u8; 16]), IntegrityError> {
    match aggregate_id {
        AggregateId::TaskRun(id) => Ok((1, id.as_bytes())),
        AggregateId::Conversation(id) => Ok((2, id.as_bytes())),
        AggregateId::Workspace(_) => {
            Err(IntegrityError::UnsupportedAggregate(aggregate_id.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    include!("integrity/tests.rs");
}
