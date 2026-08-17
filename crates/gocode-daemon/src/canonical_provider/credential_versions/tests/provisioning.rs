use std::collections::HashMap;
use std::sync::Mutex;

use super::*;

mod access;
mod source_revision;
use access::TestCredentialAccess;

struct ProvisioningNative {
    authority: NativeCredentialAuthority,
    values: Mutex<HashMap<CredentialVersionRef, Vec<u8>>>,
    creates: AtomicUsize,
}

impl ProvisioningNative {
    fn new(authority: NativeCredentialAuthority) -> Self {
        Self {
            authority,
            values: Mutex::new(HashMap::new()),
            creates: AtomicUsize::new(0),
        }
    }
}

impl NativeProviderCredentialVersionStore for ProvisioningNative {
    fn version_status(
        &self,
        reference: &CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<gocode_secure_store::ProviderCredentialStatus, SecureStoreError> {
        Ok(if self.values.lock().unwrap().contains_key(reference) {
            gocode_secure_store::ProviderCredentialStatus::Configured
        } else {
            gocode_secure_store::ProviderCredentialStatus::Missing
        })
    }

    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let authorization = self
            .authority
            .authorize_create(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        let reference = authorization.version_ref().clone();
        self.creates.fetch_add(1, Ordering::SeqCst);
        let incoming = credential.with_bytes(<[u8]>::to_vec);
        let mut values = self.values.lock().unwrap();
        let result = match values.get(&reference) {
            Some(existing) if existing == &incoming => Ok(()),
            Some(_) => Err(SecureStoreError::ProviderCredentialOperationFailed),
            None => {
                values.insert(reference, incoming);
                Ok(())
            }
        };
        drop(authorization);
        result
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
        _claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }
}

#[test]
fn restart_after_durable_prepare_reuses_exact_prepared_version() {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.path().join("credential-prepare-restart.sqlite");
    let initial = SqliteProviderCredentialLifecycleStore::open_with_connection(
        gocode_store::schema::open_managed_connection(
            &path,
            gocode_store::schema::ConnectionMode::Writer,
        )
        .unwrap(),
    )
    .unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let prepared = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    initial
        .create_prepared(PrepareCredentialVersion::new(prepared.clone()))
        .unwrap();
    drop(initial);

    let connection = gocode_store::schema::open_managed_connection(
        &path,
        gocode_store::schema::ConnectionMode::Writer,
    )
    .unwrap();
    let composed = compose_credential_lifecycle(
        connection,
        [0xC1; 16],
        1,
        ProviderCredentialId::OpenAi,
        true,
        Some(Arc::new(fixture_native)),
    )
    .unwrap();
    let active = composed.store.active_lease(&provider).unwrap().unwrap();

    assert_eq!(active.version_ref(), &prepared);
    assert_eq!(
        composed
            .store
            .next_version_ref(&provider)
            .unwrap()
            .version(),
        2
    );
}

#[test]
fn restart_after_native_create_replays_exact_version_and_activates() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("credential-native-restart.sqlite");
    let (lifecycle, native_authority) = CredentialAuthorityPair::new().split();
    let store =
        SqliteProviderCredentialLifecycleStore::open_at_with_authority(&path, lifecycle, 100)
            .unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let source = store.provision_source([0x42; 16]).unwrap();
    let provision = store
        .begin_provision(&provider, [0x41; 16], &source)
        .unwrap();
    let native = ProvisioningNative::new(native_authority);
    let material = ProviderCredentialMaterial::new(b"crash-replay-material".to_vec()).unwrap();
    let access = TestCredentialAccess::new("credential-native-restart");
    native
        .create_version(
            store.claim_native_create(&provision).unwrap(),
            &material,
            &access,
        )
        .unwrap();

    provision_active_with_material(
        &store,
        &native,
        &provider,
        ProvisionActivation {
            owner: [0xC2; 16],
            fencing_token: 1,
            now: 100,
        },
        [0x42; 16],
        Some((&material, &access)),
    )
    .unwrap();

    let active = store.active_lease(&provider).unwrap().unwrap();
    assert_eq!(active.version_ref(), provision.version_ref());
    assert!(store.pending_provision(&provider).unwrap().is_none());
    assert_eq!(native.values.lock().unwrap().len(), 1);
    assert_eq!(native.creates.load(Ordering::SeqCst), 2);
}

#[test]
fn provisioning_rejects_conflicting_operation_and_native_payload() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join("credential-provision-conflict.sqlite");
    let (lifecycle, native_authority) = CredentialAuthorityPair::new().split();
    let store =
        SqliteProviderCredentialLifecycleStore::open_at_with_authority(&path, lifecycle, 100)
            .unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let source = store.provision_source([0x53; 16]).unwrap();
    let provision = store
        .begin_provision(&provider, [0x51; 16], &source)
        .unwrap();
    let other_source = store.provision_source([0x54; 16]).unwrap();
    assert_eq!(
        store
            .begin_provision(&provider, [0x52; 16], &other_source)
            .unwrap_err(),
        gocode_provider::CredentialLifecycleError::Conflict
    );
    let native = ProvisioningNative::new(native_authority);
    let original = ProviderCredentialMaterial::new(b"original-material".to_vec()).unwrap();
    let conflicting = ProviderCredentialMaterial::new(b"conflicting-material".to_vec()).unwrap();
    let access = TestCredentialAccess::new("credential-provision-conflict");
    native
        .create_version(
            store.claim_native_create(&provision).unwrap(),
            &original,
            &access,
        )
        .unwrap();

    assert!(
        provision_active_with_material(
            &store,
            &native,
            &provider,
            ProvisionActivation {
                owner: [0xC3; 16],
                fencing_token: 1,
                now: 100,
            },
            [0x53; 16],
            Some((&conflicting, &access)),
        )
        .is_err()
    );
    assert!(
        !store
            .pending_provision(&provider)
            .unwrap()
            .unwrap()
            .native_created()
    );
    assert!(store.active_lease(&provider).unwrap().is_none());
    assert_eq!(
        store.version_state(provision.version_ref()).unwrap(),
        CredentialVersionState::Prepared
    );
}

#[test]
fn ambiguous_prepared_orphans_remain_untouched_and_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join("credential-ambiguous-prepared.sqlite");
    let store = SqliteProviderCredentialLifecycleStore::open_at(&path, 100).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let first = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let second = CredentialVersionRef::new(provider.clone(), 2).unwrap();
    for reference in [&first, &second] {
        store
            .create_prepared(PrepareCredentialVersion::new(reference.clone()))
            .unwrap();
    }

    assert!(store.reconcile(100).unwrap().native_deletions().is_empty());
    assert_eq!(
        store
            .begin_provision(
                &provider,
                [0x61; 16],
                &store.provision_source([0x62; 16]).unwrap(),
            )
            .unwrap_err(),
        gocode_provider::CredentialLifecycleError::Conflict
    );
    assert_eq!(
        store.version_state(&first).unwrap(),
        CredentialVersionState::Prepared
    );
    assert_eq!(
        store.version_state(&second).unwrap(),
        CredentialVersionState::Prepared
    );
}
