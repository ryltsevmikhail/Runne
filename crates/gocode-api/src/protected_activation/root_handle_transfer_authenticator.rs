const ROOT_HANDLE_TRANSFER_DOMAIN: &[u8] = b"gocode/root-handle-transfer/v1";

/// Authenticates native directory-handle transfers without disclosing an
/// activation key to a renderer or a transport peer.
pub struct RootHandleTransferAuthenticator {
    key: Zeroizing<[u8; 32]>,
}

impl RootHandleTransferAuthenticator {
    /// Derives an independent, zeroizing transfer key from one protected launch.
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            key: Zeroizing::new(derive_key(keys.readiness_key(), ROOT_HANDLE_TRANSFER_DOMAIN)),
        }
    }

    /// Produces a proof for one bounded native transfer record.
    #[must_use]
    pub fn authenticate_transfer(&self, record: &[u8]) -> [u8; 32] {
        authenticated_mac(&self.key, ROOT_HANDLE_TRANSFER_DOMAIN, record)
    }

    /// Verifies one native transfer record in constant time.
    #[must_use]
    pub fn verifies_transfer(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.authenticate_transfer(record).ct_eq(proof))
    }
}

impl std::fmt::Debug for RootHandleTransferAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootHandleTransferAuthenticator")
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod root_handle_transfer_authenticator_tests {
    use super::*;

    #[test]
    fn transfer_proofs_are_domain_separated_and_tamper_evident() {
        let keys = LaunchSecret::from_bytes([5; 32]).unwrap().derive_keys();
        let authenticator = RootHandleTransferAuthenticator::from_protected_activation(&keys);
        let proof = authenticator.authenticate_transfer(b"transfer");

        assert!(authenticator.verifies_transfer(b"transfer", &proof));
        assert!(!authenticator.verifies_transfer(b"replacement", &proof));
    }
}
