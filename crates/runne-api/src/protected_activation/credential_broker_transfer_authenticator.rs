const CREDENTIAL_BROKER_DAEMON_TRANSFER_DOMAIN: &[u8] =
    b"gocode/provider-credential-broker-daemon-transfer/v1";
const CREDENTIAL_BROKER_DESKTOP_TRANSFER_DOMAIN: &[u8] =
    b"gocode/provider-credential-broker-desktop-transfer/v1";
const CREDENTIAL_BROKER_KILL_READY_DOMAIN: &[u8] =
    b"gocode/provider-credential-broker-kill-ready/v1";

/// Authenticates native credential-broker endpoint transfer records.
///
/// This derives a key domain separate from root-handle transfer and from every
/// renderer-visible protocol. Both native endpoints must still bind the proof
/// to their exact protected session and native descriptors.
#[derive(Clone)]
pub struct CredentialBrokerTransferAuthenticator {
    daemon_transfer_key: Zeroizing<[u8; 32]>,
    desktop_transfer_key: Zeroizing<[u8; 32]>,
    kill_ready_key: Zeroizing<[u8; 32]>,
}

impl CredentialBrokerTransferAuthenticator {
    /// Derives the broker-transfer key from the native protected activation.
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            daemon_transfer_key: Zeroizing::new(derive_key(
                keys.readiness_key(),
                CREDENTIAL_BROKER_DAEMON_TRANSFER_DOMAIN,
            )),
            desktop_transfer_key: Zeroizing::new(derive_key(
                keys.readiness_key(),
                CREDENTIAL_BROKER_DESKTOP_TRANSFER_DOMAIN,
            )),
            kill_ready_key: Zeroizing::new(derive_key(
                keys.readiness_key(),
                CREDENTIAL_BROKER_KILL_READY_DOMAIN,
            )),
        }
    }

    /// Produces a Desktop-originated native transfer proof.
    #[must_use]
    pub fn authenticate_transfer(&self, record: &[u8]) -> [u8; 32] {
        authenticated_mac(
            &self.desktop_transfer_key,
            CREDENTIAL_BROKER_DESKTOP_TRANSFER_DOMAIN,
            record,
        )
    }

    /// Verifies a daemon-originated native transfer proof in constant time.
    #[must_use]
    pub fn verifies_transfer(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.authenticate_daemon_transfer(record).ct_eq(proof))
    }

    pub(crate) fn authenticate_daemon_transfer(&self, record: &[u8]) -> [u8; 32] {
        authenticated_mac(
            &self.daemon_transfer_key,
            CREDENTIAL_BROKER_DAEMON_TRANSFER_DOMAIN,
            record,
        )
    }

    pub(crate) fn verifies_desktop_transfer(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.authenticate_transfer(record).ct_eq(proof))
    }

    pub(crate) fn authenticate_kill_ready(&self, record: &[u8]) -> [u8; 32] {
        authenticated_mac(
            &self.kill_ready_key,
            CREDENTIAL_BROKER_KILL_READY_DOMAIN,
            record,
        )
    }

    /// Verifies a daemon-originated exact kill-ready transcript.
    #[must_use]
    pub fn verifies_kill_ready(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.authenticate_kill_ready(record).ct_eq(proof))
    }

}

/// Move-only enrollment admission bundled with its exact transfer key domain.
///
/// The admission stays opaque until the daemon's process-local request issuer
/// consumes it and adds its own non-forgeable authority seal.
pub struct ProtectedCredentialBrokerTransferAdmission {
    admission: VerifiedProtectedCredentialEnrollmentAdmission,
    authenticator: CredentialBrokerTransferAuthenticator,
}

impl ProtectedCredentialBrokerTransferAdmission {
    pub(crate) fn into_parts(
        self,
    ) -> (
        VerifiedProtectedCredentialEnrollmentAdmission,
        CredentialBrokerTransferAuthenticator,
    ) {
        (self.admission, self.authenticator)
    }
}

impl std::fmt::Debug for ProtectedCredentialBrokerTransferAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedCredentialBrokerTransferAdmission(<redacted>)")
    }
}

impl ProtectedActivationKeys {
    /// Seals the broker-transfer key to a verified admission from these exact keys.
    pub fn bind_credential_broker_transfer(
        &self,
        admission: VerifiedProtectedCredentialEnrollmentAdmission,
    ) -> Result<ProtectedCredentialBrokerTransferAdmission, LaunchAuthorityError> {
        let enrollment =
            ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(self);
        if !enrollment.owns_admission(&admission) {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(ProtectedCredentialBrokerTransferAdmission {
            admission,
            authenticator: CredentialBrokerTransferAuthenticator::from_protected_activation(self),
        })
    }
}

impl std::fmt::Debug for CredentialBrokerTransferAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialBrokerTransferAuthenticator(<redacted>)")
    }
}

#[cfg(test)]
mod credential_broker_transfer_authenticator_tests {
    use super::*;

    #[test]
    fn broker_transfer_proof_is_tamper_evident_and_isolated_from_root_transfer() {
        let keys = LaunchSecret::from_bytes([5; 32]).unwrap().derive_keys();
        let broker = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let root = RootHandleTransferAuthenticator::from_protected_activation(&keys);
        let desktop_proof = broker.authenticate_transfer(b"writer-control");
        let daemon_proof = broker.authenticate_daemon_transfer(b"writer-control");

        assert!(broker.verifies_desktop_transfer(b"writer-control", &desktop_proof));
        assert!(!broker.verifies_transfer(b"writer-control", &desktop_proof));
        assert!(broker.verifies_transfer(b"writer-control", &daemon_proof));
        assert!(!broker.verifies_desktop_transfer(b"writer-control", &daemon_proof));
        assert!(!broker.verifies_transfer(b"other-control", &daemon_proof));
        assert!(!root.verifies_transfer(b"writer-control", &desktop_proof));
    }
}
