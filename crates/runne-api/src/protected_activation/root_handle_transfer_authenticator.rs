const ROOT_HANDLE_TRANSFER_DOMAIN: &[u8] = b"runne/root-handle-transfer/v1";
const ROOT_HANDLE_OFFER_PREFIX: &[u8] = b"runne/root-handle-offer/v2";
const ROOT_HANDLE_READY_PREFIX: &[u8] = b"runne/root-handle-ready/v2";
const ROOT_HANDLE_RESULT_PREFIX: &[u8] = b"runne/root-handle-result/v2";

/// Authenticates native directory-handle transfers without disclosing an
/// activation key to a renderer or a transport peer.
#[derive(Clone)]
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

    #[must_use]
    pub(crate) fn authenticate_root_offer(&self, record: &[u8]) -> [u8; 32] {
        self.authenticate_prefixed(ROOT_HANDLE_OFFER_PREFIX, record)
    }

    #[must_use]
    pub(crate) fn authenticate_root_ready(&self, record: &[u8]) -> [u8; 32] {
        self.authenticate_prefixed(ROOT_HANDLE_READY_PREFIX, record)
    }

    #[must_use]
    pub(crate) fn authenticate_root_result(&self, record: &[u8]) -> [u8; 32] {
        self.authenticate_prefixed(ROOT_HANDLE_RESULT_PREFIX, record)
    }

    #[must_use]
    pub(crate) fn verifies_root_offer(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.authenticate_root_offer(record).ct_eq(proof))
    }

    #[must_use]
    pub(crate) fn verifies_root_ready(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.authenticate_root_ready(record).ct_eq(proof))
    }

    #[must_use]
    pub(crate) fn verifies_root_result(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.authenticate_root_result(record).ct_eq(proof))
    }

    fn authenticate_prefixed(&self, prefix: &[u8], record: &[u8]) -> [u8; 32] {
        let mut transcript = Vec::with_capacity(prefix.len() + record.len());
        transcript.extend_from_slice(prefix);
        transcript.extend_from_slice(record);
        authenticated_mac(&self.key, ROOT_HANDLE_TRANSFER_DOMAIN, &transcript)
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
