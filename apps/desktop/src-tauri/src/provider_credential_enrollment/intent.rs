use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::RngCore;

use super::CredentialIntentIpc;

const MAX_INTENTS: usize = 64;
const MAX_TTL: Duration = Duration::from_secs(30);

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the trusted prompt consumes every binding before daemon handoff"
    )
)]
struct IntentEntry {
    window: String,
    generation: u64,
    request: CredentialIntentIpc,
    protected_session: [u8; 32],
    expires: Instant,
}

/// Host-only one-use native intent; its ID has no Serde representation.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "only the trusted prompt can mint a capability before daemon handoff"
    )
)]
pub struct NativeCredentialIntent {
    id: String,
    expires: Instant,
}

impl NativeCredentialIntent {
    pub(crate) const fn expires_at(&self) -> Instant {
        self.expires
    }
}

impl fmt::Debug for NativeCredentialIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeCredentialIntent(<redacted>)")
    }
}

/// Host-only consumed intent accepted only by the protected daemon handoff.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "only the protected daemon handoff receives a consumed native intent"
    )
)]
pub struct ConsumedCredentialIntent(String);

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "only the protected daemon handoff reads the internal opaque identifier"
    )
)]
impl ConsumedCredentialIntent {
    pub fn daemon_id(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ConsumedCredentialIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsumedCredentialIntent(<redacted>)")
    }
}

/// Native owner of focused, one-use credential intent capabilities.
#[derive(Clone)]
pub struct CredentialIntentRegistry {
    ttl: Duration,
    entries: Arc<Mutex<HashMap<String, IntentEntry>>>,
}

impl CredentialIntentRegistry {
    pub fn new(ttl: Duration) -> Result<Self, CredentialIntentError> {
        if ttl.is_zero() || ttl > MAX_TTL {
            return Err(CredentialIntentError);
        }
        Ok(Self {
            ttl,
            entries: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn issue(
        &self,
        window: &str,
        generation: u64,
        request: CredentialIntentIpc,
        protected_session: [u8; 32],
        now: Instant,
    ) -> Result<NativeCredentialIntent, CredentialIntentError> {
        if window.is_empty() || generation == 0 || !request.valid() || protected_session == [0; 32]
        {
            return Err(CredentialIntentError);
        }
        let expires = now.checked_add(self.ttl).ok_or(CredentialIntentError)?;
        let mut entries = self.entries.lock().map_err(|_| CredentialIntentError)?;
        entries.retain(|_, entry| entry.expires > now);
        if entries.len() >= MAX_INTENTS {
            return Err(CredentialIntentError);
        }
        let id = random_id()?;
        entries.insert(
            id.clone(),
            IntentEntry {
                window: window.into(),
                generation,
                request,
                protected_session,
                expires,
            },
        );
        drop(entries);
        Ok(NativeCredentialIntent { id, expires })
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the protected daemon handoff consumes this after native confirmation"
        )
    )]
    pub fn consume(
        &self,
        intent: NativeCredentialIntent,
        window: &str,
        generation: u64,
        request: CredentialIntentIpc,
        protected_session: [u8; 32],
        now: Instant,
    ) -> Result<ConsumedCredentialIntent, CredentialIntentError> {
        let mut entries = self.entries.lock().map_err(|_| CredentialIntentError)?;
        let entry = entries.get(&intent.id).ok_or(CredentialIntentError)?;
        if intent.expires <= now || entry.expires != intent.expires {
            entries.remove(&intent.id);
            return Err(CredentialIntentError);
        }
        if entry.window != window
            || entry.generation != generation
            || entry.request != request
            || entry.protected_session != protected_session
        {
            return Err(CredentialIntentError);
        }
        entries.remove(&intent.id).ok_or(CredentialIntentError)?;
        drop(entries);
        Ok(ConsumedCredentialIntent(intent.id))
    }

    pub fn invalidate_window(&self, window: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, entry| entry.window != window);
        }
    }

    pub fn clear_pending(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }

    #[cfg(test)]
    pub(super) fn pending_len(&self) -> usize {
        self.entries
            .lock()
            .map_or(usize::MAX, |entries| entries.len())
    }
}

impl fmt::Debug for CredentialIntentRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialIntentRegistry(<native-only>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialIntentError;

fn random_id() -> Result<String, CredentialIntentError> {
    let mut bytes = [0; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CredentialIntentError)?;
    (bytes != [0; 32])
        .then(|| hex::encode(bytes))
        .ok_or(CredentialIntentError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_api::{ProviderCredentialEnrollmentActionV2, ProviderCredentialProviderV2};

    fn request() -> CredentialIntentIpc {
        CredentialIntentIpc {
            provider: ProviderCredentialProviderV2::OpenAi,
            action: ProviderCredentialEnrollmentActionV2::Pair,
            expected_revision: 7,
            renderer_generation: 4,
            verification_kind: None,
        }
    }

    #[test]
    fn intent_is_one_use_and_bound_to_window_renderer_action_provider_and_session() {
        let registry = CredentialIntentRegistry::new(Duration::from_secs(1)).unwrap();
        let now = Instant::now();
        let request = request();
        let session = [9; 32];
        let intent = registry.issue("main", 4, request, session, now).unwrap();
        assert!(
            registry
                .consume(intent, "other", 4, request, session, now)
                .is_err()
        );
        let intent = registry.issue("main", 4, request, session, now).unwrap();
        let consumed = registry
            .consume(intent, "main", 4, request, session, now)
            .unwrap();
        assert_eq!(consumed.daemon_id().len(), 64);
    }

    #[test]
    fn stale_or_expired_intent_is_rejected_and_page_invalidation_fences_the_window() {
        let registry = CredentialIntentRegistry::new(Duration::from_secs(1)).unwrap();
        let now = Instant::now();
        let request = request();
        let intent = registry.issue("main", 4, request, [9; 32], now).unwrap();
        assert!(intent.expires_at() > now);
        assert!(
            registry
                .consume(
                    intent,
                    "main",
                    4,
                    request,
                    [9; 32],
                    now + Duration::from_secs(1)
                )
                .is_err()
        );
        let intent = registry.issue("main", 4, request, [9; 32], now).unwrap();
        registry.invalidate_window("main");
        assert!(
            registry
                .consume(intent, "main", 4, request, [9; 32], now)
                .is_err()
        );
    }
}
