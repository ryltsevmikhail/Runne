use std::collections::HashMap;
use std::sync::{Arc, Barrier, Mutex};

use gocode_provider::{
    CredentialAuthorityPair, CredentialDispatchCapability, CredentialGcClaim, CredentialLease,
    CredentialVersionRef, NativeCredentialAuthority, NativeCredentialDeletionProof, ProviderId,
};
use gocode_secure_store::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy,
    ProviderCredentialMaterial, SecureStoreError,
};

use super::controlled_executable;

enum VersionState {
    Incomplete,
    Complete(Vec<u8>),
}

struct OpaqueVersionFixture {
    authority: NativeCredentialAuthority,
    values: Mutex<HashMap<CredentialVersionRef, VersionState>>,
}

impl OpaqueVersionFixture {
    fn new(authority: NativeCredentialAuthority) -> Self {
        Self {
            authority,
            values: Mutex::new(HashMap::new()),
        }
    }

    fn inject_incomplete(&self, reference: CredentialVersionRef) {
        self.values
            .lock()
            .unwrap()
            .insert(reference, VersionState::Incomplete);
    }
}

impl NativeProviderCredentialVersionStore for OpaqueVersionFixture {
    fn create_version(
        &self,
        reference: CredentialVersionRef,
        credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let incoming = credential.with_bytes(<[u8]>::to_vec);
        let mut values = self.values.lock().unwrap();
        match values.get(&reference) {
            Some(VersionState::Complete(existing)) if existing == &incoming => Ok(()),
            Some(VersionState::Complete(_)) => {
                Err(SecureStoreError::ProviderCredentialOperationFailed)
            }
            Some(VersionState::Incomplete) | None => {
                values.insert(reference, VersionState::Complete(incoming));
                drop(values);
                Ok(())
            }
        }
    }

    fn load_version(
        &self,
        capability: &CredentialDispatchCapability,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        let reference = self
            .authority
            .authorize_load(capability)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        match self.values.lock().unwrap().get(reference) {
            Some(VersionState::Complete(value)) => ProviderCredentialMaterial::new(value.clone()),
            Some(VersionState::Incomplete) => Err(SecureStoreError::CredentialEnrollmentIncomplete),
            None => Err(SecureStoreError::ProviderCredentialNotFound),
        }
    }

    fn delete_version(
        &self,
        claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        let reference = self
            .authority
            .authorize_delete(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?
            .clone();
        self.values.lock().unwrap().remove(&reference);
        self.authority
            .prove_deletion(claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)
    }
}

#[test]
fn opaque_version_operations_never_expose_secret_bytes() {
    let (lifecycle, native) = CredentialAuthorityPair::new().split();
    let fixture = OpaqueVersionFixture::new(native);
    let reference = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 7).unwrap();
    let secret = b"opaque-fixture-secret-62cf".to_vec();
    let material = ProviderCredentialMaterial::new(secret.clone()).unwrap();
    let executable = controlled_executable();
    fixture
        .create_version(reference.clone(), &material, &executable.access)
        .unwrap();
    fixture
        .create_version(reference.clone(), &material, &executable.access)
        .unwrap();
    let lease = CredentialLease::new(reference.clone(), [0xA1; 16], i64::MAX, 7).unwrap();
    let active = lifecycle.issue_dispatch(lease);
    let loaded = fixture.load_version(&active, &executable.access).unwrap();
    assert_eq!(loaded.with_bytes(<[u8]>::to_vec), secret);
    for rendered in [
        format!("{reference:?}"),
        format!("{material:?}"),
        format!("{loaded:?}"),
    ] {
        assert!(!rendered.contains("opaque-fixture-secret-62cf"));
    }
    let proof = fixture
        .delete_version(lifecycle.issue_gc(reference.clone()))
        .unwrap();
    assert_eq!(lifecycle.verify_deletion(&proof).unwrap(), &reference);
    let replay = fixture
        .delete_version(lifecycle.issue_gc(reference.clone()))
        .unwrap();
    assert_eq!(lifecycle.verify_deletion(&replay).unwrap(), &reference);
    assert_eq!(
        fixture
            .load_version(&active, &executable.access)
            .unwrap_err(),
        SecureStoreError::ProviderCredentialNotFound
    );
}

#[test]
fn foreign_capabilities_cannot_load_or_delete_native_version() {
    let (_, native) = CredentialAuthorityPair::new().split();
    let fixture = OpaqueVersionFixture::new(native);
    let reference = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 8).unwrap();
    let executable = controlled_executable();
    let material = ProviderCredentialMaterial::new(b"authority-bound-secret".to_vec()).unwrap();
    fixture
        .create_version(reference.clone(), &material, &executable.access)
        .unwrap();
    let (foreign, _) = CredentialAuthorityPair::new().split();
    let lease = CredentialLease::new(reference.clone(), [0xB2; 16], i64::MAX, 8).unwrap();
    assert_eq!(
        fixture
            .load_version(&foreign.issue_dispatch(lease), &executable.access)
            .unwrap_err(),
        SecureStoreError::CredentialAccessDenied
    );
    assert_eq!(
        fixture
            .delete_version(foreign.issue_gc(reference))
            .unwrap_err(),
        SecureStoreError::CredentialAccessDenied
    );
}

#[test]
fn immutable_create_repairs_incomplete_state_and_serializes_competing_bytes() {
    let (lifecycle, native) = CredentialAuthorityPair::new().split();
    let fixture = Arc::new(OpaqueVersionFixture::new(native));
    let reference = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 9).unwrap();
    let executable = controlled_executable();
    fixture.inject_incomplete(reference.clone());
    let repaired = ProviderCredentialMaterial::new(b"repaired-secret".to_vec()).unwrap();
    fixture
        .create_version(reference.clone(), &repaired, &executable.access)
        .unwrap();

    let competing = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 10).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let results = [b"first-secret".to_vec(), b"second-secret".to_vec()].map(|bytes| {
        let fixture = Arc::clone(&fixture);
        let barrier = Arc::clone(&barrier);
        let reference = competing.clone();
        let access = executable.access.clone();
        std::thread::spawn(move || {
            let material = ProviderCredentialMaterial::new(bytes).unwrap();
            barrier.wait();
            fixture.create_version(reference, &material, &access)
        })
    });
    barrier.wait();
    assert_eq!(
        results
            .into_iter()
            .flat_map(|result| result.join().unwrap())
            .count(),
        1
    );
    let active =
        lifecycle.issue_dispatch(CredentialLease::new(reference, [0xA1; 16], i64::MAX, 9).unwrap());
    assert_eq!(
        fixture
            .load_version(&active, &executable.access)
            .unwrap()
            .with_bytes(<[u8]>::to_vec),
        b"repaired-secret"
    );
}
