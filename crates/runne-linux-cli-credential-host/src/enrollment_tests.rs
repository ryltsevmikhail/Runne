use super::*;
use runne_secure_store::{
    ProviderCredentialAccessPolicy, ProviderCredentialSourceRevision, SecureStoreError,
};
use std::sync::Mutex;

struct Native {
    authority: NativeCredentialAuthority,
    stored: Mutex<Option<(CredentialVersionRef, [u8; 16])>>,
    fault: u8,
}
impl NativeProviderCredentialVersionStore for Native {
    fn version_status(
        &self,
        _: &CredentialVersionRef,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        Ok(
            if self.stored.lock().unwrap().is_some() && self.fault != 2 {
                ProviderCredentialStatus::Configured
            } else {
                ProviderCredentialStatus::Missing
            },
        )
    }
    fn version_source_revision(
        &self,
        _: &CredentialVersionRef,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSourceRevision, SecureStoreError> {
        ProviderCredentialSourceRevision::new(if self.fault == 3 {
            [9; 16]
        } else {
            self.stored.lock().unwrap().as_ref().unwrap().1
        })
    }
    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        _: &ProviderCredentialMaterial,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let authorization = self
            .authority
            .authorize_create(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        assert_eq!(authorization.version_ref(), claim.version_ref());
        if self.fault == 1 {
            return Err(SecureStoreError::Unavailable);
        }
        *self.stored.lock().unwrap() =
            Some((claim.version_ref().clone(), *claim.source_revision_id()));
        Ok(())
    }
    fn load_version(
        &self,
        _: &CredentialDispatchCapability,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        panic!("enrollment must never dispatch or read raw material back")
    }
    fn delete_version(
        &self,
        _: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        panic!("pair must never delete")
    }
}

#[test]
fn native_readback_activates_exact_online_version_and_survives_store_reopen() {
    exercise(0);
}
#[test]
fn native_failure_missing_readback_and_wrong_revision_never_activate() {
    for fault in [1, 2, 3] {
        exercise(fault);
    }
}
fn exercise(fault: u8) {
    let directory = tempfile::Builder::new()
        .prefix("cli-host-")
        .tempdir_in(std::env::current_exe().unwrap().parent().unwrap())
        .unwrap();
    let policy = Arc::new(crate::test_policy::policy(directory.path()));
    let path = directory.path().join("lifecycle.sqlite");
    let (lifecycle, native_authority) = CredentialAuthorityPair::new().split();
    let (enrollment, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store = Arc::new(
        SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &path,
            lifecycle.clone(),
            enrollment,
        )
        .unwrap(),
    );
    let native = Native {
        authority: native_authority,
        stored: Mutex::new(None),
        fault,
    };
    let result = pair_with(
        store.clone(),
        lifecycle,
        measurements,
        &native,
        policy,
        [8; 16],
        1,
        ProviderCredentialMaterial::new(b"synthetic-key".to_vec()).unwrap(),
    );
    let provider = ProviderId::new("deepseek").unwrap();
    let snapshot = store.begin_admission_snapshot(&provider).unwrap();
    if fault == 0 {
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(snapshot.active_version().unwrap().version(), 1);
        assert_eq!(snapshot.lifecycle_revision().get(), 2);
        assert_eq!(snapshot.readiness_revision().get(), 2);
        assert_eq!(snapshot.fence().get(), 2);
    } else {
        assert!(result.is_err());
        assert!(snapshot.active_version().is_none());
        assert_eq!(snapshot.lifecycle_revision().get(), 1);
        assert_eq!(snapshot.readiness_revision().get(), 1);
    }
    drop(store);
    let reopened = SqliteProviderCredentialLifecycleStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .begin_admission_snapshot(&provider)
            .unwrap()
            .active_version()
            .is_some(),
        fault == 0
    );
}
