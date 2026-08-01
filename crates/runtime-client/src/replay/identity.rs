use super::validation::{decode_lower_hex, validate_canonical_event};
use super::wire::{self, CanonicalEventWire};
use super::{
    Arc, CanonicalId, HashMap, MAXIMUM_TRACKED_IDENTITIES, Mutex, ReplayClientError,
    ReplayClientErrorKind, ReplayCursor, ReplayDelivery, ReplayDeliveryDisposition, ReplayScope,
    ReplaySessionId, VecDeque,
};

#[derive(Clone, Eq, PartialEq)]
struct SeenIdentity {
    cursor: ReplayCursor,
    canonical_digest: [u8; 32],
}

#[derive(Default)]
struct IdentityState {
    seen: HashMap<CanonicalId, SeenIdentity>,
    order: VecDeque<CanonicalId>,
    last_sequence: Option<u64>,
    scope: Option<ReplayScope>,
}

/// Shareable identity history for inclusive reconnect deduplication.
#[derive(Clone, Default)]
pub struct ReplayIdentityTracker {
    inner: Arc<Mutex<IdentityState>>,
}

impl ReplayIdentityTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

pub(super) struct DeliveryValidator {
    scope: ReplayScope,
    binding_id: Option<[u8; 16]>,
    identities: ReplayIdentityTracker,
}

impl DeliveryValidator {
    pub(super) const fn new(scope: ReplayScope, identities: ReplayIdentityTracker) -> Self {
        Self {
            scope,
            binding_id: None,
            identities,
        }
    }

    pub(super) fn validate(
        &mut self,
        wire_event: CanonicalEventWire,
        cursor_value: String,
        session_id: ReplaySessionId,
    ) -> Result<ReplayDelivery, ReplayClientError> {
        let cursor = wire::cursor(cursor_value)?;
        let binding = decode_lower_hex::<16>(&wire_event.replay_binding_id)
            .filter(|value| *value != [0; 16])
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::BindingMismatch))?;
        match self.binding_id {
            Some(expected) if expected != binding => {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::BindingMismatch,
                ));
            }
            None => self.binding_id = Some(binding),
            _ => {}
        }

        let canonical = validate_canonical_event(wire_event)?;
        if canonical.aggregate_kind != self.scope.aggregate_kind
            || canonical.aggregate_id != self.scope.aggregate_id
        {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::AggregateMismatch,
            ));
        }

        let mut identities = self
            .identities
            .inner
            .lock()
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Integrity))?;
        match identities.scope {
            Some(expected) if expected != self.scope => {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::BindingMismatch,
                ));
            }
            None => identities.scope = Some(self.scope),
            _ => {}
        }
        let identity = SeenIdentity {
            cursor: cursor.clone(),
            canonical_digest: canonical.canonical_digest,
        };
        let disposition = if let Some(existing) = identities.seen.get(&canonical.event_id) {
            if existing != &identity {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::EventIdentityConflict,
                ));
            }
            ReplayDeliveryDisposition::Duplicate
        } else {
            if identities
                .last_sequence
                .is_some_and(|last| last.checked_add(1) != Some(canonical.sequence))
            {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::NonMonotonicSequence,
                ));
            }
            identities.last_sequence = Some(canonical.sequence);
            identities.seen.insert(canonical.event_id, identity);
            identities.order.push_back(canonical.event_id);
            if identities.order.len() > MAXIMUM_TRACKED_IDENTITIES {
                let oldest = identities
                    .order
                    .pop_front()
                    .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::Integrity))?;
                identities.seen.remove(&oldest);
            }
            ReplayDeliveryDisposition::New
        };
        drop(identities);

        Ok(ReplayDelivery {
            event: canonical,
            cursor,
            disposition,
            session_id,
        })
    }
}
