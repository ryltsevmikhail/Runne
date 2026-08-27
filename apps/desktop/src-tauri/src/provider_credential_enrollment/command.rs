#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::time::{Duration, Instant};

#[cfg(test)]
use rand::RngCore;
use runne_api::{
    ProviderCredentialEnrollmentActionV2, ProviderCredentialProviderV2,
    ProviderCredentialVerificationKindV2,
};
use serde::Deserialize;

#[cfg(test)]
const MAX_INTENTS: usize = 64;
#[cfg(test)]
const MAX_TTL: Duration = Duration::from_secs(30);

/// Renderer input. There is intentionally no credential or native intent ID.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialIntentIpc {
    pub(crate) provider: ProviderCredentialProviderV2,
    pub(crate) action: ProviderCredentialEnrollmentActionV2,
    pub(crate) expected_revision: u64,
    pub(crate) verification_kind: Option<ProviderCredentialVerificationKindV2>,
}

impl CredentialIntentIpc {
    pub(crate) fn valid(self) -> bool {
        self.expected_revision != 0
            && !(matches!(
                self.action,
                ProviderCredentialEnrollmentActionV2::Pair
                    | ProviderCredentialEnrollmentActionV2::MigrateLegacy
            ) && self.verification_kind.is_some())
            && !(self.action == ProviderCredentialEnrollmentActionV2::Revoke
                && self.verification_kind.is_some())
    }
}

#[cfg(test)]
struct IntentEntry {
    window: String,
    generation: u64,
    request: CredentialIntentIpc,
    protected_session: [u8; 32],
    expires: Instant,
}

/// Host-only one-use registry. IDs never return to the renderer.
#[cfg(test)]
#[derive(Clone)]
struct NativeCredentialIntentRegistry {
    ttl: Duration,
    entries: Arc<Mutex<HashMap<String, IntentEntry>>>,
}

#[cfg(test)]
impl NativeCredentialIntentRegistry {
    fn new(ttl: Duration) -> Result<Self, ()> {
        if ttl.is_zero() || ttl > MAX_TTL {
            return Err(());
        }
        Ok(Self {
            ttl,
            entries: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn issue(
        &self,
        window: &str,
        generation: u64,
        request: CredentialIntentIpc,
        protected_session: [u8; 32],
        now: Instant,
    ) -> Result<(), ()> {
        if window.is_empty() || generation == 0 || !request.valid() || protected_session == [0; 32]
        {
            return Err(());
        }
        let expires = now.checked_add(self.ttl).ok_or(())?;
        let mut entries = self.entries.lock().map_err(|_| ())?;
        entries.retain(|_, entry| entry.expires > now);
        if entries.len() >= MAX_INTENTS {
            return Err(());
        }
        let id = random_id();
        entries.insert(
            id,
            IntentEntry {
                window: window.into(),
                generation,
                request,
                protected_session,
                expires,
            },
        );
        drop(entries);
        Ok(())
    }

    fn consume(
        &self,
        window: &str,
        generation: u64,
        request: CredentialIntentIpc,
        protected_session: [u8; 32],
        now: Instant,
    ) -> Result<(), ()> {
        let mut entries = self.entries.lock().map_err(|_| ())?;
        let found = entries
            .iter()
            .find_map(|(id, entry)| {
                (entry.window == window
                    && entry.generation == generation
                    && entry.request == request
                    && entry.protected_session == protected_session
                    && entry.expires > now)
                    .then(|| id.clone())
            })
            .ok_or(())?;
        entries.remove(&found).map(|_| ()).ok_or(())
    }
}

#[cfg(test)]
fn random_id() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> CredentialIntentIpc {
        CredentialIntentIpc {
            provider: ProviderCredentialProviderV2::OpenAi,
            action: ProviderCredentialEnrollmentActionV2::Pair,
            expected_revision: 7,
            verification_kind: None,
        }
    }

    #[test]
    fn ipc_recursively_rejects_credential_and_renderer_native_intent_id() {
        for value in [
            json!({"provider":"openai","action":"pair","expectedRevision":7,"credential":"secret"}),
            json!({"provider":"openai","action":"pair","expectedRevision":7,"nativeIntentId":"forged"}),
        ] {
            assert!(serde_json::from_value::<CredentialIntentIpc>(value).is_err());
        }
    }

    #[test]
    fn intent_is_one_use_and_bound_to_window_renderer_action_provider_and_session() {
        let registry = NativeCredentialIntentRegistry::new(Duration::from_secs(1)).unwrap();
        let now = Instant::now();
        let request = request();
        let session = [9; 32];
        registry.issue("main", 4, request, session, now).unwrap();
        assert!(registry.consume("other", 4, request, session, now).is_err());
        assert!(registry.consume("main", 4, request, session, now).is_ok());
        assert!(registry.consume("main", 4, request, session, now).is_err());
    }

    #[test]
    fn stale_or_expired_intent_is_rejected() {
        let registry = NativeCredentialIntentRegistry::new(Duration::from_secs(1)).unwrap();
        let now = Instant::now();
        let request = request();
        registry.issue("main", 4, request, [9; 32], now).unwrap();
        assert!(registry.consume("main", 5, request, [9; 32], now).is_err());
        assert!(
            registry
                .consume("main", 4, request, [9; 32], now + Duration::from_secs(1))
                .is_err()
        );
    }
}
