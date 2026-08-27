const CREDENTIAL_BROKER_TRANSFER_DOMAIN: &[u8] =
    b"gocode/provider-credential-broker-transfer/v1";

/// Authenticates native credential-broker endpoint transfer records.
///
/// This derives a key domain separate from root-handle transfer and from every
/// renderer-visible protocol. Both native endpoints must still bind the proof
/// to their exact protected session and native descriptors.
#[derive(Clone)]
pub struct CredentialBrokerTransferAuthenticator {
    key: Zeroizing<[u8; 32]>,
}

impl CredentialBrokerTransferAuthenticator {
    /// Derives the broker-transfer key from the native protected activation.
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            key: Zeroizing::new(derive_key(
                keys.readiness_key(),
                CREDENTIAL_BROKER_TRANSFER_DOMAIN,
            )),
        }
    }

    /// Produces a proof for exactly one native descriptor-transfer record.
    #[must_use]
    pub fn authenticate_transfer(&self, record: &[u8]) -> [u8; 32] {
        authenticated_mac(&self.key, CREDENTIAL_BROKER_TRANSFER_DOMAIN, record)
    }

    /// Verifies a descriptor-transfer record in constant time.
    #[must_use]
    pub fn verifies_transfer(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.authenticate_transfer(record).ct_eq(proof))
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
        let proof = broker.authenticate_transfer(b"writer-control");

        assert!(broker.verifies_transfer(b"writer-control", &proof));
        assert!(!broker.verifies_transfer(b"other-control", &proof));
        assert!(!root.verifies_transfer(b"writer-control", &proof));
    }
}
