use std::collections::HashMap;

use base64::Engine;
use gocode_domain::id::SecretRefId;
use gocode_domain::security::SecretRef;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::prohibited_content::{ProhibitedContentGuard, SharedSecretRegistry};

/// Ephemeral secret material. Its bytes are visible only inside this crate.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Temporary authorized secret handle retained for compatibility with callers.
pub struct SecretHandle {
    pub secret_ref: SecretRef,
    value: SecretValue,
    valid: bool,
}

impl SecretHandle {
    pub fn value(&self) -> Option<&[u8]> {
        self.valid.then_some(self.value.bytes())
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Returns the typed carrier without exposing its bytes.
    pub fn as_secret_value(&self) -> &SecretValue {
        &self.value
    }
}

impl Drop for SecretHandle {
    fn drop(&mut self) {
        self.valid = false;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("reference not found")]
    ReferenceNotFound,
    #[error("reference revoked")]
    ReferenceRevoked,
    #[error("reference version is no longer current")]
    ReferenceVersionMismatch,
    #[error("secret registry unavailable")]
    Unavailable,
}

struct SecretEntry {
    value: SecretValue,
    state: SecretState,
    version: u64,
    _name: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretState {
    Active,
    Revoked,
}

/// Private, shared secret-registry state. It is never serialized or exposed.
pub(crate) struct SecretRegistryState {
    secrets: HashMap<SecretRefId, SecretEntry>,
    policy_epoch: u64,
    unavailable: bool,
    derived_representations: Zeroizing<Vec<Vec<u8>>>,
}

impl SecretRegistryState {
    pub(crate) fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            policy_epoch: 1,
            unavailable: false,
            derived_representations: Zeroizing::new(Vec::new()),
        }
    }

    pub(crate) fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    pub(crate) fn is_available(&self) -> bool {
        !self.unavailable
    }

    pub(crate) fn matches_active_representation(&self, bytes: &[u8]) -> bool {
        self.derived_representations.iter().any(|representation| {
            !representation.is_empty()
                && bytes
                    .windows(representation.len())
                    .any(|window| window == representation)
        })
    }

    fn advance_epoch(&mut self) -> Result<(), SecretError> {
        self.policy_epoch = match self.policy_epoch.checked_add(1) {
            Some(next) => next,
            None => {
                self.unavailable = true;
                return Err(SecretError::Unavailable);
            }
        };
        Ok(())
    }

    fn rebuild_representations(&mut self) {
        self.derived_representations.zeroize();
        let mut next = Vec::new();
        for entry in self.secrets.values() {
            if entry.state == SecretState::Active && !entry.value.bytes().is_empty() {
                add_representations(&mut next, entry.value.bytes());
            }
        }
        self.derived_representations = Zeroizing::new(next);
    }
}

fn add_representations(representations: &mut Vec<Vec<u8>>, value: &[u8]) {
    representations.push(value.to_vec());
    let standard = base64::engine::general_purpose::STANDARD.encode(value);
    representations.push(standard.as_bytes().to_vec());
    representations.push(standard.trim_end_matches('=').as_bytes().to_vec());
    representations.push(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(value)
            .into_bytes(),
    );
    representations.push(hex::encode(value).into_bytes());
    representations.push(hex::encode_upper(value).into_bytes());
}

/// Capability-gated owner of secret material and prohibited-content registry.
pub struct SecretBroker {
    registry: SharedSecretRegistry,
}

impl SecretBroker {
    pub fn new() -> Self {
        Self {
            registry: std::sync::Arc::new(std::sync::RwLock::new(SecretRegistryState::new())),
        }
    }

    /// Returns a guard backed by this broker's current registry.
    pub fn prohibited_content_guard(&self) -> ProhibitedContentGuard {
        ProhibitedContentGuard::new(std::sync::Arc::clone(&self.registry))
    }

    /// Registers material under a fresh opaque reference.
    pub fn register(&mut self, name: &str, value: Vec<u8>) -> Result<SecretRef, SecretError> {
        let secret_ref_id = SecretRefId::from_bytes(*Uuid::now_v7().as_bytes());
        let secret_ref = SecretRef::new(secret_ref_id, 1).map_err(|_| SecretError::Unavailable)?;
        let mut state = self
            .registry
            .write()
            .map_err(|_| SecretError::Unavailable)?;
        if !state.is_available() {
            return Err(SecretError::Unavailable);
        }
        state.advance_epoch()?;
        state.secrets.insert(
            secret_ref_id,
            SecretEntry {
                value: SecretValue::new(value),
                state: SecretState::Active,
                version: secret_ref.version(),
                _name: name.to_owned(),
            },
        );
        state.rebuild_representations();
        Ok(secret_ref)
    }

    /// Rotates material and returns the next opaque version of the reference.
    pub fn rotate(
        &mut self,
        secret_ref: &SecretRef,
        value: Vec<u8>,
    ) -> Result<SecretRef, SecretError> {
        let mut state = self
            .registry
            .write()
            .map_err(|_| SecretError::Unavailable)?;
        if !state.is_available() {
            return Err(SecretError::Unavailable);
        }
        let entry = state
            .secrets
            .get(&secret_ref.secret_ref_id())
            .ok_or(SecretError::ReferenceNotFound)?;
        if entry.state == SecretState::Revoked {
            return Err(SecretError::ReferenceRevoked);
        }
        if entry.version != secret_ref.version() {
            return Err(SecretError::ReferenceVersionMismatch);
        }
        let next_version = entry
            .version
            .checked_add(1)
            .ok_or(SecretError::Unavailable)?;
        state.advance_epoch()?;
        let entry = state
            .secrets
            .get_mut(&secret_ref.secret_ref_id())
            .ok_or(SecretError::Unavailable)?;
        entry.value = SecretValue::new(value);
        entry.version = next_version;
        state.rebuild_representations();
        SecretRef::new(secret_ref.secret_ref_id(), next_version)
            .map_err(|_| SecretError::Unavailable)
    }

    pub fn resolve(
        &self,
        secret_ref: &SecretRef,
        authorized: bool,
    ) -> Result<SecretHandle, SecretError> {
        if !authorized {
            return Err(SecretError::Unauthorized);
        }
        let state = self.registry.read().map_err(|_| SecretError::Unavailable)?;
        if !state.is_available() {
            return Err(SecretError::Unavailable);
        }
        let entry = state
            .secrets
            .get(&secret_ref.secret_ref_id())
            .ok_or(SecretError::ReferenceNotFound)?;
        match entry.state {
            SecretState::Revoked => Err(SecretError::ReferenceRevoked),
            SecretState::Active if entry.version != secret_ref.version() => {
                Err(SecretError::ReferenceVersionMismatch)
            }
            SecretState::Active => Ok(SecretHandle {
                secret_ref: secret_ref.clone(),
                value: SecretValue::new(entry.value.bytes().to_vec()),
                valid: true,
            }),
        }
    }

    pub fn revoke(&mut self, secret_ref: &SecretRef) -> Result<(), SecretError> {
        let mut state = self
            .registry
            .write()
            .map_err(|_| SecretError::Unavailable)?;
        if !state.is_available() {
            return Err(SecretError::Unavailable);
        }
        let entry = state
            .secrets
            .get(&secret_ref.secret_ref_id())
            .ok_or(SecretError::ReferenceNotFound)?;
        if entry.version != secret_ref.version() {
            return Err(SecretError::ReferenceVersionMismatch);
        }
        if entry.state == SecretState::Active {
            state.advance_epoch()?;
            let entry = state
                .secrets
                .get_mut(&secret_ref.secret_ref_id())
                .ok_or(SecretError::Unavailable)?;
            entry.state = SecretState::Revoked;
            state.rebuild_representations();
        }
        Ok(())
    }
}

impl Default for SecretBroker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_requires_authorization() {
        let mut broker = SecretBroker::new();
        let secret_ref = broker.register("api_key", b"sk-abc123".to_vec()).unwrap();
        assert!(matches!(
            broker.resolve(&secret_ref, false),
            Err(SecretError::Unauthorized)
        ));
    }

    #[test]
    fn authorized_resolve_works() {
        let mut broker = SecretBroker::new();
        let secret_ref = broker.register("api_key", b"sk-abc123".to_vec()).unwrap();
        let handle = broker.resolve(&secret_ref, true).unwrap();
        assert!(handle.is_valid());
        assert_eq!(handle.value().unwrap(), b"sk-abc123");
    }

    #[test]
    fn revoked_secret_rejected() {
        let mut broker = SecretBroker::new();
        let secret_ref = broker.register("api_key", b"sk-abc123".to_vec()).unwrap();
        broker.revoke(&secret_ref).unwrap();
        assert!(matches!(
            broker.resolve(&secret_ref, true),
            Err(SecretError::ReferenceRevoked)
        ));
    }
}
