use hmac::{Hmac, Mac};
use runne_api::{ProviderCredentialEnrollmentHostError, ProviderCredentialOperationHandleV2};
use runne_provider::CredentialOperationId;
use sha2::Sha256;
use zeroize::Zeroizing;

const HANDLE_DOMAIN: &[u8] = b"gocode/provider-credential-operation-handle/v2\0";
const RENDEZVOUS_DOMAIN: &[u8] = b"gocode/provider-credential-broker-rendezvous/v1\0";

/// Daemon-owned issuer for opaque public operation handles.
pub(crate) struct ProviderCredentialOperationHandleIssuer {
    key: Zeroizing<[u8; 32]>,
}

impl ProviderCredentialOperationHandleIssuer {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self::new(*self.key)
    }

    pub(crate) fn issue(
        &self,
        operation_id: CredentialOperationId,
    ) -> ProviderCredentialOperationHandleV2 {
        let bytes = self.tagged_bytes(HANDLE_DOMAIN, operation_id);
        ProviderCredentialOperationHandleV2::from_bytes(bytes)
            .expect("non-zero operation id always produces a non-zero public handle")
    }

    /// Issues the distinct opaque identifier used only by the broker rendezvous.
    pub(crate) fn issue_broker_rendezvous_id(&self, operation_id: CredentialOperationId) -> String {
        hex::encode(self.tagged_bytes(RENDEZVOUS_DOMAIN, operation_id))
    }

    pub(super) fn resolve(
        &self,
        handle: ProviderCredentialOperationHandleV2,
    ) -> Result<CredentialOperationId, ProviderCredentialEnrollmentHostError> {
        self.resolve_tagged_bytes(HANDLE_DOMAIN, handle.as_bytes())
    }

    #[cfg(any(
        test,
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    pub(crate) fn resolve_broker_rendezvous_id(
        &self,
        rendezvous_id: &str,
    ) -> Result<CredentialOperationId, ProviderCredentialEnrollmentHostError> {
        let bytes: [u8; 48] = hex::decode(rendezvous_id)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?
            .try_into()
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.resolve_tagged_bytes(RENDEZVOUS_DOMAIN, &bytes)
    }

    fn resolve_tagged_bytes(
        &self,
        domain: &[u8],
        bytes: &[u8; 48],
    ) -> Result<CredentialOperationId, ProviderCredentialEnrollmentHostError> {
        let operation: [u8; 16] = bytes[..16]
            .try_into()
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).expect("fixed HMAC key length");
        mac.update(domain);
        mac.update(&operation);
        mac.verify_slice(&bytes[16..])
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        CredentialOperationId::from_bytes(operation)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn tagged_bytes(&self, domain: &[u8], operation_id: CredentialOperationId) -> [u8; 48] {
        let operation = operation_id.as_bytes();
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).expect("fixed HMAC key length");
        mac.update(domain);
        mac.update(&operation);
        let mut bytes = [0_u8; 48];
        bytes[..16].copy_from_slice(&operation);
        bytes[16..].copy_from_slice(&mac.finalize().into_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use runne_provider::CredentialOperationId;

    use super::ProviderCredentialOperationHandleIssuer;

    #[test]
    fn handles_are_deterministic_only_within_one_process_local_key() {
        let operation = CredentialOperationId::from_bytes([7; 16]).unwrap();
        let issuer = ProviderCredentialOperationHandleIssuer::new([8; 32]);
        let same = issuer.duplicate();
        let foreign = ProviderCredentialOperationHandleIssuer::new([9; 32]);
        let handle = issuer.issue(operation);

        assert_eq!(same.resolve(handle).unwrap(), operation);
        assert!(foreign.resolve(handle).is_err());
    }
}
