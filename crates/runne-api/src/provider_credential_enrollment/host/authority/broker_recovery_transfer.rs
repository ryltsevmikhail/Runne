impl ProviderCredentialRequestAuthorityIssuer {
    /// Creates endpoint-transfer authority only, without manufacturing native intent.
    /// The protected host must verify recovery acceptance separately; the durable
    /// store witness remains mandatory before any credential ticket is issued.
    pub fn issue_recovery_broker_transfer(
        &self,
        keys: &ProtectedActivationKeys,
        authority: &ProviderCredentialBaseRequestAuthority,
    ) -> Result<ProviderCredentialBrokerTransferAuthority, ProviderCredentialEnrollmentHostError> {
        verify_seal(&self.seal, &authority.seal)?;
        Ok(ProviderCredentialBrokerTransferAuthority {
            seal: Arc::clone(&self.seal),
            transfer_seal: Arc::new(AuthoritySeal),
            protected_session_binding: *authority.protected_session_id(),
            authenticator: CredentialBrokerTransferAuthenticator::from_protected_activation(keys),
            writer_evidence_available: true,
        })
    }
}

#[cfg(test)]
#[path = "broker_recovery_transfer_tests.rs"]
mod broker_recovery_transfer_tests;
