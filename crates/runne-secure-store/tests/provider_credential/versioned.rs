use std::collections::HashMap;
use std::sync::{Arc, Barrier, Mutex};

use runne_provider::{
    CredentialAuthorityPair, CredentialDispatchCapability, CredentialGcClaim, CredentialLease,
    CredentialLifecycleAuthority, CredentialLifecycleError, CredentialNativeCreateClaim,
    CredentialNativeCreateValidator, CredentialVersionRef, NativeCredentialAuthority,
    NativeCredentialDeletionProof, ProviderId,
};
use runne_secure_store::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy,
    ProviderCredentialMaterial, ProviderCredentialStatus, SecureStoreError,
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
    fn version_status(
        &self,
        reference: &CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        Ok(match self.values.lock().unwrap().get(reference) {
            Some(VersionState::Complete(_)) => ProviderCredentialStatus::Configured,
            Some(VersionState::Incomplete) => {
                return Err(SecureStoreError::CredentialEnrollmentIncomplete);
            }
            None => ProviderCredentialStatus::Missing,
        })
    }

    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let mut values = self.values.lock().unwrap();
        let authorization = self
            .authority
            .authorize_create(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        let reference = authorization.version_ref().clone();
        let incoming = credential.with_bytes(<[u8]>::to_vec);
        let result = match values.get(&reference) {
            Some(VersionState::Complete(existing)) if existing == &incoming => Ok(()),
            Some(VersionState::Complete(_)) => {
                Err(SecureStoreError::ProviderCredentialOperationFailed)
            }
            Some(VersionState::Incomplete) | None => {
                values.insert(reference, VersionState::Complete(incoming));
                drop(values);
                Ok(())
            }
        };
        drop(authorization);
        result
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

fn create_claim(
    authority: &CredentialLifecycleAuthority,
    reference: CredentialVersionRef,
    discriminator: u8,
) -> CredentialNativeCreateClaim {
    let source = authority
        .issue_provision_source([discriminator; 16])
        .unwrap();
    authority
        .native_create_issuer()
        .unwrap()
        .issue_native_create(reference, &source, Arc::new(PreparedValidator))
        .unwrap()
}

struct PreparedValidator;

impl CredentialNativeCreateValidator for PreparedValidator {
    fn validate(&self) -> Result<(), CredentialLifecycleError> {
        Ok(())
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
        .create_version(
            create_claim(&lifecycle, reference.clone(), 1),
            &material,
            &executable.access,
        )
        .unwrap();
    assert_eq!(
        fixture
            .version_status(&reference, &executable.access)
            .unwrap(),
        ProviderCredentialStatus::Configured
    );
    fixture
        .create_version(
            create_claim(&lifecycle, reference.clone(), 1),
            &material,
            &executable.access,
        )
        .unwrap();
    let lease = CredentialLease::new(reference.clone(), [0xA1; 16], i64::MAX, 7).unwrap();
    let active = lifecycle.issue_dispatch(lease);
    let loaded = fixture.load_version(&active, &executable.access).unwrap();
    assert_eq!(loaded.with_bytes(<[u8]>::to_vec), secret);
    assert!(!format!("{reference:?}").contains("opaque-fixture-secret-62cf"));
    let proof = fixture
        .delete_version(lifecycle.issue_gc(reference.clone()))
        .unwrap();
    assert_eq!(
        fixture
            .version_status(&reference, &executable.access)
            .unwrap(),
        ProviderCredentialStatus::Missing
    );
    assert_eq!(lifecycle.verify_deletion(&proof).unwrap(), &reference);
    let replay = fixture
        .delete_version(lifecycle.issue_gc(reference.clone()))
        .unwrap();
    assert_eq!(lifecycle.verify_deletion(&replay).unwrap(), &reference);
    assert_eq!(
        fixture
            .load_version(&active, &executable.access)
            .err()
            .expect("deleted version stays absent"),
        SecureStoreError::ProviderCredentialNotFound
    );
    drop(executable);
}

#[test]
fn foreign_capabilities_cannot_load_or_delete_native_version() {
    let (lifecycle, native) = CredentialAuthorityPair::new().split();
    let fixture = OpaqueVersionFixture::new(native);
    let reference = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 8).unwrap();
    let executable = controlled_executable();
    let material = ProviderCredentialMaterial::new(b"authority-bound-secret".to_vec()).unwrap();
    fixture
        .create_version(
            create_claim(&lifecycle, reference.clone(), 2),
            &material,
            &executable.access,
        )
        .unwrap();
    let (foreign, _) = CredentialAuthorityPair::new().split();
    let lease = CredentialLease::new(reference.clone(), [0xB2; 16], i64::MAX, 8).unwrap();
    assert_eq!(
        fixture
            .load_version(&foreign.issue_dispatch(lease), &executable.access)
            .err()
            .expect("foreign dispatch rejected"),
        SecureStoreError::CredentialAccessDenied
    );
    assert_eq!(
        fixture
            .create_version(
                create_claim(&foreign, reference.clone(), 3),
                &material,
                &executable.access,
            )
            .unwrap_err(),
        SecureStoreError::CredentialAccessDenied
    );
    assert_eq!(
        fixture
            .delete_version(foreign.issue_gc(reference))
            .unwrap_err(),
        SecureStoreError::CredentialAccessDenied
    );
    drop(executable);
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
        .create_version(
            create_claim(&lifecycle, reference.clone(), 4),
            &repaired,
            &executable.access,
        )
        .unwrap();

    let competing = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 10).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let [first_claim, second_claim] =
        [5, 6].map(|id| create_claim(&lifecycle, competing.clone(), id));
    let results = [
        (b"first-secret".to_vec(), first_claim),
        (b"second-secret".to_vec(), second_claim),
    ]
    .map(|(bytes, claim)| {
        let fixture = Arc::clone(&fixture);
        let barrier = Arc::clone(&barrier);
        let access = executable.access.clone();
        std::thread::spawn(move || {
            let material = ProviderCredentialMaterial::new(bytes).unwrap();
            barrier.wait();
            fixture.create_version(claim, &material, &access)
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
    drop(executable);
}
