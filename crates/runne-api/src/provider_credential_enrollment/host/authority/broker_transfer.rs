use crate::CredentialBrokerTransferAuthenticator;

/// Process-local witness for the exact request-authority issuer domain.
pub struct ProviderCredentialBrokerHandoffWitness {
    seal: Arc<AuthoritySeal>,
}

/// Move-only broker transfer authority sealed by the daemon request issuer.
pub struct ProviderCredentialBrokerTransferAuthority {
    seal: Arc<AuthoritySeal>,
    protected_session_binding: [u8; 32],
    authenticator: CredentialBrokerTransferAuthenticator,
}

impl ProviderCredentialRequestAuthorityIssuer {
    /// Consumes one protected admission and seals its transfer key to this issuer.
    pub fn issue_from_verified_enrollment_with_broker_transfer(
        &self,
        request: VerifiedProtectedCredentialEnrollmentRequest,
        admission: ProtectedCredentialBrokerTransferAdmission,
    ) -> Result<
        (
            ProviderCredentialBaseRequestAuthority,
            ProviderCredentialIntentConsumptionProof,
            ProviderCredentialBrokerTransferAuthority,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let (admission, authenticator) = admission.into_parts();
        let protected_session_binding = admission.protected_session_binding();
        let (authority, proof) = self.issue_from_verified_enrollment(request, admission)?;
        Ok((
            authority,
            proof,
            ProviderCredentialBrokerTransferAuthority {
                seal: Arc::clone(&self.seal),
                protected_session_binding,
                authenticator,
            },
        ))
    }
}

impl ProviderCredentialBaseRequestAuthority {
    /// Retains only the opaque issuer domain needed by a later daemon handoff.
    #[must_use]
    pub fn credential_broker_handoff_witness(&self) -> ProviderCredentialBrokerHandoffWitness {
        ProviderCredentialBrokerHandoffWitness {
            seal: Arc::clone(&self.seal),
        }
    }
}

impl ProviderCredentialBrokerHandoffWitness {
    /// Rejects a substituted current base authority from another issuer domain.
    #[must_use]
    pub fn matches_authority(&self, authority: &ProviderCredentialBaseRequestAuthority) -> bool {
        Arc::ptr_eq(&self.seal, &authority.seal)
    }
}

impl ProviderCredentialBrokerTransferAuthority {
    /// Binds the transfer key to both the daemon issuer and current session.
    #[must_use]
    pub fn matches_handoff(
        &self,
        witness: &ProviderCredentialBrokerHandoffWitness,
        protected_session_binding: &[u8; 32],
    ) -> bool {
        Arc::ptr_eq(&self.seal, &witness.seal)
            && self.protected_session_binding == *protected_session_binding
    }

    /// Borrows the authenticated transfer key while retaining the issuer seal.
    #[must_use]
    pub fn transfer_authenticator(&self) -> &CredentialBrokerTransferAuthenticator {
        &self.authenticator
    }
}

impl fmt::Debug for ProviderCredentialBrokerTransferAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderCredentialBrokerTransferAuthority(<authenticated>)")
    }
}
