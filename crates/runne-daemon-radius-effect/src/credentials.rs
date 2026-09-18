use bytes::Bytes;
use reqwest::header::HeaderValue;
use runne_provider::{DispatchError, ProviderPreEffectRejection};
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial, SecureStoreError,
};
use runne_store::provider::ProviderEffectStartReceipt;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::Ready;

pub fn materialize(
    materializer: &Arc<dyn ProviderCredentialDispatchMaterializer>,
    ready: &Ready,
    receipt: &ProviderEffectStartReceipt,
) -> Result<Zeroizing<Vec<u8>>, DispatchError> {
    let (lifecycle, fence) = ready
        .credential
        .point_of_use_revisions()
        .map_err(|_| DispatchError::MaybeDispatched)?;
    let read = ProviderCredentialDispatchRead::new(
        ready.credential.native_capability(),
        lifecycle,
        fence,
        receipt.credential_read_receipt_digest(),
    )
    .map_err(|_| DispatchError::MaybeDispatched)?;
    materializer
        .materialize_active(read)
        .map(|value: ProviderCredentialMaterial| {
            value.with_bytes(|bytes| Zeroizing::new(bytes.to_vec()))
        })
        .map_err(|error| match error {
            SecureStoreError::ProviderCredentialNotFound => DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::CredentialUnavailable,
            ),
            _ => DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::CredentialAccessDenied,
            ),
        })
}

pub fn bearer_header(value: &Zeroizing<Vec<u8>>) -> Result<HeaderValue, DispatchError> {
    let mut wire = Zeroizing::new(Vec::with_capacity(7 + value.len()));
    wire.extend_from_slice(b"Bearer ");
    wire.extend_from_slice(value);
    let mut header = HeaderValue::from_maybe_shared(Bytes::from_owner(HeaderOwner { bytes: wire }))
        .map_err(|_| DispatchError::MaybeDispatched)?;
    header.set_sensitive(true);
    Ok(header)
}

struct HeaderOwner {
    bytes: Zeroizing<Vec<u8>>,
}
impl AsRef<[u8]> for HeaderOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for HeaderOwner {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.bytes);
    }
}
