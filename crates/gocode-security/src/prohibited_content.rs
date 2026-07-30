//! In-memory classification of material registered with the secret broker.

use std::sync::{Arc, RwLock};

use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};

use crate::broker::secret::SecretRegistryState;

/// Shared private state used by the secret broker and its content guard.
pub(crate) type SharedSecretRegistry = Arc<RwLock<SecretRegistryState>>;

/// Concrete, in-memory implementation of [`ProhibitedContentPort`].
///
/// It never returns matching evidence: callers receive only a disposition and
/// the policy epoch that was observed.
#[derive(Clone)]
pub struct ProhibitedContentGuard {
    registry: SharedSecretRegistry,
}

impl ProhibitedContentGuard {
    pub(crate) fn new(registry: SharedSecretRegistry) -> Self {
        Self { registry }
    }

    /// Rejects a typed secret carrier without materializing its bytes.
    pub fn inspect_secret_value(
        &self,
        _boundary: CanonicalContentBoundary,
        _value: &crate::broker::secret::SecretValue,
    ) -> Result<ContentDisposition, ContentGuardError> {
        let state = self
            .registry
            .read()
            .map_err(|_| ContentGuardError::Unavailable)?;
        if !state.is_available() {
            return Err(ContentGuardError::Unavailable);
        }
        Ok(ContentDisposition::Prohibited {
            policy_epoch: state.policy_epoch(),
        })
    }
}

impl ProhibitedContentPort for ProhibitedContentGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        let state = self
            .registry
            .read()
            .map_err(|_| ContentGuardError::Unavailable)?;
        if !state.is_available() {
            return Err(ContentGuardError::Unavailable);
        }
        let disposition = if state.matches_active_representation(bytes) {
            ContentDisposition::Prohibited {
                policy_epoch: state.policy_epoch(),
            }
        } else {
            ContentDisposition::Allowed {
                policy_epoch: state.policy_epoch(),
            }
        };
        Ok(disposition)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    #[test]
    fn poisoned_registry_fails_closed() {
        let registry = Arc::new(RwLock::new(SecretRegistryState::new()));
        let poisoned = Arc::clone(&registry);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _lock = poisoned.write().unwrap();
            panic!("test-only lock poisoning");
        }));

        let guard = ProhibitedContentGuard::new(registry);
        assert_eq!(
            guard.inspect(
                CanonicalContentBoundary::CanonicalMutation,
                b"ordinary text"
            ),
            Err(ContentGuardError::Unavailable)
        );
    }
}
