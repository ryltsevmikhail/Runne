use super::*;
use gocode_secure_store::{ProviderCredentialSource, ProviderCredentialSourceRevision};

struct LegacySourceFixture {
    revision: Option<[u8; 16]>,
}

impl LegacyCredentialSource for LegacySourceFixture {
    fn load_source(
        &self,
        _provider: ProviderCredentialId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        let revision = self
            .revision
            .ok_or(SecureStoreError::ProviderCredentialSourceRevisionUnavailable)?;
        Ok(ProviderCredentialSource::new(
            ProviderCredentialMaterial::new(b"stable-legacy-source".to_vec())?,
            ProviderCredentialSourceRevision::new(revision)?,
        ))
    }
}

#[test]
fn crash_after_prepared_with_unchanged_source_revision_completes() {
    let fixture = ProvisionFixture::new("unchanged-source");
    let prepared = fixture.prepare([0x31; 16]);

    provision_active_from_legacy_source(
        &fixture.store,
        &fixture.native,
        &fixture.provider,
        activation([0x32; 16]),
        &LegacySourceFixture {
            revision: Some([0x31; 16]),
        },
        &fixture.access,
    )
    .unwrap();

    let active = fixture
        .store
        .active_lease(&fixture.provider)
        .unwrap()
        .unwrap();
    assert_eq!(active.version_ref(), prepared.version_ref());
    assert_eq!(fixture.native.creates.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .store
            .pending_provision(&fixture.provider)
            .unwrap()
            .is_none()
    );
}

#[test]
fn changed_source_revision_conflicts_before_native_create() {
    let fixture = ProvisionFixture::new("changed-source");
    let prepared = fixture.prepare([0x33; 16]);

    assert!(
        provision_active_from_legacy_source(
            &fixture.store,
            &fixture.native,
            &fixture.provider,
            activation([0x34; 16]),
            &LegacySourceFixture {
                revision: Some([0x35; 16]),
            },
            &fixture.access,
        )
        .is_err()
    );

    assert_eq!(fixture.native.creates.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.store.version_state(prepared.version_ref()).unwrap(),
        CredentialVersionState::Prepared
    );
}

#[test]
fn missing_source_revision_blocks_before_native_create() {
    let fixture = ProvisionFixture::new("missing-source");
    let prepared = fixture.prepare([0x36; 16]);

    assert!(
        provision_active_from_legacy_source(
            &fixture.store,
            &fixture.native,
            &fixture.provider,
            activation([0x37; 16]),
            &LegacySourceFixture { revision: None },
            &fixture.access,
        )
        .is_err()
    );

    assert_eq!(fixture.native.creates.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.store.version_state(prepared.version_ref()).unwrap(),
        CredentialVersionState::Prepared
    );
}

#[test]
fn crash_after_native_created_does_not_request_another_create_claim() {
    let fixture = ProvisionFixture::new("native-created-source");
    let prepared = fixture.prepare([0x38; 16]);
    let material = ProviderCredentialMaterial::new(b"stable-legacy-source".to_vec()).unwrap();
    fixture
        .native
        .create_version(
            fixture.store.claim_native_create(&prepared).unwrap(),
            &material,
            &fixture.access,
        )
        .unwrap();
    let native_created = fixture.store.mark_native_created(&prepared).unwrap();

    provision_active_from_legacy_source(
        &fixture.store,
        &fixture.native,
        &fixture.provider,
        activation([0x39; 16]),
        &LegacySourceFixture {
            revision: Some([0x38; 16]),
        },
        &fixture.access,
    )
    .unwrap();

    let active = fixture
        .store
        .active_lease(&fixture.provider)
        .unwrap()
        .unwrap();
    assert_eq!(active.version_ref(), native_created.version_ref());
    assert_eq!(fixture.native.creates.load(Ordering::SeqCst), 1);
}

const fn activation(owner: [u8; 16]) -> ProvisionActivation {
    ProvisionActivation {
        owner,
        fencing_token: 1,
        now: 100,
    }
}

struct ProvisionFixture {
    _directory: tempfile::TempDir,
    store: SqliteProviderCredentialLifecycleStore,
    native: ProvisioningNative,
    provider: ProviderId,
    access: TestCredentialAccess,
}

impl ProvisionFixture {
    fn new(label: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("{label}.sqlite"));
        let (lifecycle, native_authority) = CredentialAuthorityPair::new().split();
        let store =
            SqliteProviderCredentialLifecycleStore::open_at_with_authority(&path, lifecycle, 100)
                .unwrap();
        Self {
            _directory: directory,
            store,
            native: ProvisioningNative::new(native_authority),
            provider: ProviderId::new("openai").unwrap(),
            access: TestCredentialAccess::new(label),
        }
    }

    fn prepare(&self, revision: [u8; 16]) -> gocode_store::provider::CredentialProvision {
        let source = self.store.provision_source(revision).unwrap();
        self.store
            .begin_provision(&self.provider, [0x30; 16], &source)
            .unwrap()
    }
}
