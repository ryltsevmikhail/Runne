use std::sync::atomic::{AtomicUsize, Ordering};

use gocode_provider::{
    CredentialAuthorityPair, CredentialDispatchCapability, CredentialGcClaim, CredentialLease,
    CredentialNativeCreateClaim, CredentialVersionRef, CredentialVersionState,
    NativeCredentialAuthority, NativeCredentialDeletionProof, PrepareCredentialVersion,
    ProviderCredentialVersionStore, ProviderId, RevokeCredentialVersion,
};
use gocode_secure_store::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy,
    ProviderCredentialMaterial, SecureStoreError,
};

use super::*;

mod provisioning;
mod startup;

struct DeletingNative {
    authority: NativeCredentialAuthority,
    deletes: AtomicUsize,
}

pub(super) fn fixture_native(
    authority: NativeCredentialAuthority,
) -> Arc<dyn NativeProviderCredentialVersionStore> {
    Arc::new(DeletingNative {
        authority,
        deletes: AtomicUsize::new(0),
    })
}

impl NativeProviderCredentialVersionStore for DeletingNative {
    fn version_status(
        &self,
        _reference: &CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<gocode_secure_store::ProviderCredentialStatus, SecureStoreError> {
        Ok(gocode_secure_store::ProviderCredentialStatus::Configured)
    }

    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        _credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.authority
            .authorize_create(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn load_version(
        &self,
        _capability: &CredentialDispatchCapability,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn delete_version(
        &self,
        claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        self.authority
            .authorize_delete(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        self.deletes.fetch_add(1, Ordering::SeqCst);
        self.authority
            .prove_deletion(claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)
    }
}

#[test]
fn production_reconcile_deletes_native_before_permanent_tombstone() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("credential-reconcile.sqlite");
    let (lifecycle, native_authority) = CredentialAuthorityPair::new().split();
    let store =
        SqliteProviderCredentialLifecycleStore::open_at_with_authority(&path, lifecycle, 100)
            .unwrap();
    let native = DeletingNative {
        authority: native_authority,
        deletes: AtomicUsize::new(0),
    };
    let reference = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 1).unwrap();
    store
        .create_prepared(PrepareCredentialVersion::new(reference.clone()))
        .unwrap();
    store
        .activate(CredentialLease::new(reference.clone(), [0xA1; 16], 500, 17).unwrap())
        .unwrap();
    store
        .revoke_and_fence(RevokeCredentialVersion::new(reference.clone(), 17).unwrap())
        .unwrap();

    reconcile_native(&store, &native, 100).unwrap();
    assert_eq!(native.deletes.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.version_state(&reference).unwrap(),
        CredentialVersionState::Deleted
    );
    assert!(store.tombstone_digest(&reference).unwrap().is_some());

    reconcile_native(&store, &native, 100).unwrap();
    assert_eq!(native.deletes.load(Ordering::SeqCst), 1);
}
