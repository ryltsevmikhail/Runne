const KILL_BINDING_DIGEST_DOMAIN: &[u8] =
    b"GOCODE_PROVIDER_CREDENTIAL_BROKER_KILL_BINDING_V1\0";

impl ProviderCredentialBrokerKillBindingV1 {
    /// Hashes every exact ownership field, rejecting incomplete tuples.
    pub fn binding_digest(&self) -> Result<[u8; 32], ProviderCredentialEnrollmentHostError> {
        if !self.valid() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let mut hasher = Sha256::new();
        hasher.update(KILL_BINDING_DIGEST_DOMAIN);
        for field in [
            self.start,
            self.image,
            self.release,
            self.channel,
            self.key,
            self.writer_kill_public_key,
        ] {
            hasher.update(field);
        }
        Ok(hasher.finalize().into())
    }
}
