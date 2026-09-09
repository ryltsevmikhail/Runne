use crate::{ProviderCredentialAccessPolicy, SecureStoreError};
use runne_provider::CredentialVersionRef;

/// Fully loads and immediately drops one exact native credential in the
/// opaque local real-process lane. No material leaves this function.
///
/// # Errors
///
/// Returns a closed error outside the validated local lane or when the exact
/// native credential cannot be loaded by the current reader.
pub fn prove_current_reader_can_load_exact(
    reference: &CredentialVersionRef,
    access: &ProviderCredentialAccessPolicy,
) -> Result<(), SecureStoreError> {
    if !runne_api::test_support::local_native_enrollment_enabled() {
        return Err(SecureStoreError::CredentialAccessDenied);
    }
    prove_native_load(reference, access)
}

#[cfg(target_os = "macos")]
fn prove_native_load(
    reference: &CredentialVersionRef,
    access: &ProviderCredentialAccessPolicy,
) -> Result<(), SecureStoreError> {
    use crate::{NativeProviderCredentialStore, NativeProviderCredentialVersionStore};
    use runne_provider::{CredentialAuthorityPair, CredentialLease};

    let (issuer, native) = CredentialAuthorityPair::new().split();
    let store = NativeProviderCredentialStore::new_versioned(native);
    let lease = CredentialLease::new(reference.clone(), [1; 16], i64::MAX, 1)
        .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
    let material = store.load_version(&issuer.issue_dispatch(lease), access)?;
    let used = material.with_bytes(|bytes| std::hint::black_box(!bytes.is_empty()));
    used.then_some(())
        .ok_or(SecureStoreError::CorruptProviderCredential)
}

#[cfg(not(target_os = "macos"))]
const fn prove_native_load(
    _reference: &CredentialVersionRef,
    _access: &ProviderCredentialAccessPolicy,
) -> Result<(), SecureStoreError> {
    Err(SecureStoreError::UnsupportedSecureStoreBackend)
}
