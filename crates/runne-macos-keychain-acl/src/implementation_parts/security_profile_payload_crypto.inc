const PAYLOAD_KEY_BYTES: usize = 32;
const MAX_WRAPPED_PAYLOAD_KEY_BYTES: usize = 512;
const PAYLOAD_KEY_ALGORITHM: Algorithm = Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM;

impl SecurityProfileProcessLock {
    /// Wraps a 32-byte payload key with this profile's Secure Enclave public key.
    ///
    /// The caller keeps the payload key only in zeroizing memory and stores the
    /// returned ECIES envelope next to the sealed payload. Wrapping is bound to
    /// the profile digest held by this guard.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainAclError::InvalidProfileBinding`] for a mismatched
    /// profile, and [`KeychainAclError::InvalidSeal`] or
    /// [`KeychainAclError::OperationFailed`] when the native key cannot wrap the
    /// supplied key material.
    pub fn encrypt_payload_key(
        &self,
        profile_identity_digest: [u8; 32],
        payload_key: &[u8],
    ) -> Result<Vec<u8>, KeychainAclError> {
        if profile_identity_digest != self.profile_identity_digest {
            return Err(KeychainAclError::InvalidProfileBinding);
        }
        if payload_key.len() != PAYLOAD_KEY_BYTES {
            return Err(KeychainAclError::InvalidSeal);
        }
        let public_key = self
            .private_key
            .public_key()
            .ok_or(KeychainAclError::OperationFailed)?;
        let wrapped = public_key
            .encrypt_data(PAYLOAD_KEY_ALGORITHM, payload_key)
            .map_err(|_| KeychainAclError::OperationFailed)?;
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_PAYLOAD_KEY_BYTES {
            return Err(KeychainAclError::OperationFailed);
        }
        Ok(wrapped)
    }

    /// Unwraps an ECIES payload-key envelope with this profile's Secure Enclave key.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainAclError::InvalidProfileBinding`] for a mismatched
    /// profile and [`KeychainAclError::InvalidSeal`] for a truncated, oversized,
    /// foreign or corrupted envelope. No plaintext key material is returned on
    /// failure.
    pub fn decrypt_payload_key(
        &self,
        profile_identity_digest: [u8; 32],
        wrapped: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, KeychainAclError> {
        if profile_identity_digest != self.profile_identity_digest {
            return Err(KeychainAclError::InvalidProfileBinding);
        }
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_PAYLOAD_KEY_BYTES {
            return Err(KeychainAclError::InvalidSeal);
        }
        let payload_key = self
            .private_key
            .decrypt_data(PAYLOAD_KEY_ALGORITHM, wrapped)
            .map_err(|_| KeychainAclError::InvalidSeal)?;
        if payload_key.len() != PAYLOAD_KEY_BYTES {
            return Err(KeychainAclError::InvalidSeal);
        }
        Ok(zeroize::Zeroizing::new(payload_key))
    }
}
