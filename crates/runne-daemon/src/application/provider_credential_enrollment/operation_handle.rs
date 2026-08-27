use hmac::{Hmac, Mac};
use runne_api::{ProviderCredentialEnrollmentHostError, ProviderCredentialOperationHandleV2};
use runne_provider::CredentialOperationId;
use sha2::Sha256;
use zeroize::Zeroizing;

#[allow(dead_code)]
const HANDLE_DOMAIN: &[u8] = b"gocode/provider-credential-operation-handle/v2\0";

/// Daemon-owned issuer for opaque public operation handles.
#[allow(dead_code)]
pub(super) struct ProviderCredentialOperationHandleIssuer {
    key: Zeroizing<[u8; 32]>,
}

#[allow(dead_code)]
impl ProviderCredentialOperationHandleIssuer {
    pub(super) fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    pub(super) fn duplicate(&self) -> Self {
        Self::new(*self.key)
    }

    pub(super) fn issue(
        &self,
        operation_id: CredentialOperationId,
    ) -> ProviderCredentialOperationHandleV2 {
        let operation = operation_id.as_bytes();
        let mut bytes = [0_u8; 48];
        bytes[..16].copy_from_slice(&operation);
        bytes[16..].copy_from_slice(&self.tag(&operation));
        ProviderCredentialOperationHandleV2::from_bytes(bytes)
            .expect("non-zero operation id always produces a non-zero public handle")
    }

    pub(super) fn resolve(
        &self,
        handle: ProviderCredentialOperationHandleV2,
    ) -> Result<CredentialOperationId, ProviderCredentialEnrollmentHostError> {
        let bytes = handle.as_bytes();
        let operation: [u8; 16] = bytes[..16]
            .try_into()
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).expect("fixed HMAC key length");
        mac.update(HANDLE_DOMAIN);
        mac.update(&operation);
        mac.verify_slice(&bytes[16..])
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        CredentialOperationId::from_bytes(operation)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn tag(&self, operation: &[u8; 16]) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).expect("fixed HMAC key length");
        mac.update(HANDLE_DOMAIN);
        mac.update(operation);
        mac.finalize().into_bytes().into()
    }
}
