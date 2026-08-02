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
