use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef {
    pub secret_id: String,
    pub version: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SecretHandle {
    pub secret_ref: SecretRef,
    value: Vec<u8>,
    valid: bool,
}

impl SecretHandle {
    pub fn value(&self) -> Option<&[u8]> {
        self.valid.then_some(&self.value)
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }
}

impl Drop for SecretHandle {
    fn drop(&mut self) {
        self.value.fill(0);
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
    #[error("reference expired")]
    ReferenceExpired,
}

pub struct SecretBroker {
    secrets: HashMap<String, (Vec<u8>, SecretState)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretState {
    Active,
    Revoked,
}

impl SecretBroker {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: &str, value: Vec<u8>) -> SecretRef {
        self.secrets
            .insert(name.to_string(), (value, SecretState::Active));
        SecretRef {
            secret_id: name.to_string(),
            version: Some(1),
        }
    }

    pub fn resolve(
        &self,
        secret_ref: &SecretRef,
        authorized: bool,
    ) -> Result<SecretHandle, SecretError> {
        if !authorized {
            return Err(SecretError::Unauthorized);
        }
        let (value, state) = self
            .secrets
            .get(&secret_ref.secret_id)
            .ok_or(SecretError::ReferenceNotFound)?;
        match state {
            SecretState::Revoked => Err(SecretError::ReferenceRevoked),
            SecretState::Active => Ok(SecretHandle {
                secret_ref: secret_ref.clone(),
                value: value.clone(),
                valid: true,
            }),
        }
    }

    pub fn revoke(&mut self, secret_ref: &SecretRef) -> Result<(), SecretError> {
        let (_, state) = self
            .secrets
            .get_mut(&secret_ref.secret_id)
            .ok_or(SecretError::ReferenceNotFound)?;
        *state = SecretState::Revoked;
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
        let secret_ref = broker.register("api_key", b"sk-abc123".to_vec());
        assert!(matches!(
            broker.resolve(&secret_ref, false),
            Err(SecretError::Unauthorized)
        ));
    }

    #[test]
    fn authorized_resolve_works() {
        let mut broker = SecretBroker::new();
        let secret_ref = broker.register("api_key", b"sk-abc123".to_vec());
        let handle = broker.resolve(&secret_ref, true).unwrap();
        assert!(handle.is_valid());
        assert_eq!(handle.value().unwrap(), b"sk-abc123");
    }

    #[test]
    fn revoked_secret_rejected() {
        let mut broker = SecretBroker::new();
        let secret_ref = broker.register("api_key", b"sk-abc123".to_vec());
        broker.revoke(&secret_ref).unwrap();
        assert!(matches!(
            broker.resolve(&secret_ref, true),
            Err(SecretError::ReferenceRevoked)
        ));
    }

    #[test]
    fn handle_zeroized_on_drop() {
        let mut broker = SecretBroker::new();
        let secret_ref = broker.register("key", b"secret-data".to_vec());
        let handle = broker.resolve(&secret_ref, true).unwrap();
        assert!(handle.is_valid());
        drop(handle);
    }
}
