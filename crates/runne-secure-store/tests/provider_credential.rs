use runne_secure_store::{
    MAX_PROVIDER_CREDENTIAL_BYTES, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialMaterial, ProviderCredentialMaterialKind, ProviderCredentialSource,
    ProviderCredentialSourceRevision, ProviderCredentialStatus, ProviderCredentialStore,
    SecureStoreError,
};
use zeroize::Zeroizing;
struct ControlledExecutable {
    access: ProviderCredentialAccessPolicy,
    _permissions: CurrentExecutablePermissions,
}

static CURRENT_EXECUTABLE_PERMISSIONS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct CurrentExecutablePermissions {
    path: std::path::PathBuf,
    _lock: std::sync::MutexGuard<'static, ()>,
    #[cfg(unix)]
    original_mode: u32,
}

impl Drop for CurrentExecutablePermissions {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(
                &self.path,
                std::fs::Permissions::from_mode(self.original_mode),
            );
        }
    }
}

fn controlled_executable() -> ControlledExecutable {
    let lock = CURRENT_EXECUTABLE_PERMISSIONS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let executable = std::env::current_exe().expect("current test executable");
    #[cfg(unix)]
    let original_mode = {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&executable)
            .expect("current executable metadata")
            .permissions()
            .mode();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500))
            .expect("restrict current executable");
        mode
    };
    let access = ProviderCredentialAccessPolicy::new(&executable, &executable)
        .expect("controlled executable access policy");
    ControlledExecutable {
        access,
        _permissions: CurrentExecutablePermissions {
            path: executable,
            _lock: lock,
            #[cfg(unix)]
            original_mode,
        },
    }
}

struct StatusOnlyStore(ProviderCredentialStatus);

impl ProviderCredentialStore for StatusOnlyStore {
    fn provider_credential_status(
        &self,
        provider: ProviderCredentialId,
        _expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        assert_eq!(provider, ProviderCredentialId::OpenAi);
        Ok(self.0)
    }

    fn store_provider_credential(
        &self,
        _provider: ProviderCredentialId,
        _credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn load_provider_credential(
        &self,
        _provider: ProviderCredentialId,
        _expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn delete_provider_credential(
        &self,
        _provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn migrate_provider_credential_access(
        &self,
        _provider: ProviderCredentialId,
        _current: &ProviderCredentialAccessPolicy,
        _replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }
}

#[test]
fn credential_material_is_bounded_single_line_and_move_only() {
    for invalid in [
        Vec::new(),
        vec![b'x'; MAX_PROVIDER_CREDENTIAL_BYTES + 1],
        b"first\nsecond".to_vec(),
        b"first\rsecond".to_vec(),
        b"prefix\0suffix".to_vec(),
    ] {
        let Err(error) = ProviderCredentialMaterial::new(invalid) else {
            panic!("invalid material unexpectedly accepted");
        };
        assert_eq!(error, SecureStoreError::InvalidProviderCredential);
    }

    let marker = b"provider-secret-marker-7f3c".to_vec();
    let credential = ProviderCredentialMaterial::new(marker.clone()).unwrap();
    assert_eq!(credential.with_bytes(<[u8]>::to_vec), marker);
    let maximum = ProviderCredentialMaterial::new(vec![b'x'; MAX_PROVIDER_CREDENTIAL_BYTES])
        .expect("exact maximum is accepted");
    assert_eq!(
        maximum.with_bytes(<[u8]>::len),
        MAX_PROVIDER_CREDENTIAL_BYTES
    );
    assert_eq!(
        ProviderCredentialSourceRevision::new([0; 16]).unwrap_err(),
        SecureStoreError::InvalidProviderCredential
    );
    let source = ProviderCredentialSource::new(
        ProviderCredentialMaterial::new(marker).unwrap(),
        ProviderCredentialSourceRevision::new([0x71; 16]).unwrap(),
    );
    let rendered = format!("{:?}", source.revision());
    assert!(!rendered.contains("provider-secret-marker-7f3c"));
    assert!(!rendered.contains("71717171"));
}

#[test]
fn credential_material_transfers_typed_zeroizing_allocation_without_copying() {
    let bytes = Zeroizing::new(b"provider-secret-transfer".to_vec());
    let allocation = bytes.as_ptr();

    let material = ProviderCredentialMaterial::from_zeroizing(bytes).expect("valid material");
    let (kind, transferred): (ProviderCredentialMaterialKind, Zeroizing<Vec<u8>>) =
        material.into_zeroizing();

    assert_eq!(kind, ProviderCredentialMaterialKind::Legacy);
    assert_eq!(transferred.as_ptr(), allocation);
    assert_eq!(transferred.as_slice(), b"provider-secret-transfer");
    drop(transferred);
}

#[test]
fn native_oauth_kind_survives_zeroizing_transfer() {
    let material = ProviderCredentialMaterial::new_native_oauth(b"native-oauth-envelope".to_vec())
        .expect("valid OAuth material");
    let allocation = material.with_bytes(<[u8]>::as_ptr);

    let (kind, transferred) = material.into_zeroizing();

    assert_eq!(kind, ProviderCredentialMaterialKind::NativeOAuth);
    assert_eq!(transferred.as_ptr(), allocation);
    assert_eq!(transferred.as_slice(), b"native-oauth-envelope");
    drop(transferred);
}

#[test]
fn provider_identity_and_status_vocabulary_are_exact() {
    assert_eq!(ProviderCredentialId::OpenAi.account(), "openai");
    assert_eq!(ProviderCredentialId::DeepSeek.account(), "deepseek");
    assert_eq!(
        ProviderCredentialStatus::Configured.to_string(),
        "configured"
    );
    assert_eq!(ProviderCredentialStatus::Missing.to_string(), "missing");
    assert_eq!(
        ProviderCredentialStatus::Unsupported.to_string(),
        "unsupported"
    );

    let store = StatusOnlyStore(ProviderCredentialStatus::Configured);
    let executable = controlled_executable();
    assert_eq!(
        store
            .provider_credential_status(ProviderCredentialId::OpenAi, &executable.access)
            .unwrap(),
        ProviderCredentialStatus::Configured
    );
    assert_eq!(
        store
            .load_provider_credential_source(ProviderCredentialId::OpenAi, &executable.access)
            .err()
            .expect("source revision unavailable"),
        SecureStoreError::ProviderCredentialSourceRevisionUnavailable
    );
    drop(executable);
}

#[cfg(target_os = "macos")]
#[test]
fn native_store_routes_deepseek_to_distinct_missing_account() {
    use runne_secure_store::NativeProviderCredentialStore;

    let store = NativeProviderCredentialStore::new();
    let executable = controlled_executable();
    assert_eq!(
        store
            .provider_credential_status(ProviderCredentialId::DeepSeek, &executable.access)
            .unwrap(),
        ProviderCredentialStatus::Missing
    );
    drop(executable);
}

#[test]
fn credential_errors_are_closed_and_never_carry_secret_or_path_context() {
    let marker = "provider-secret-marker-7f3c";
    for error in [
        SecureStoreError::UnsupportedSecureStoreBackend,
        SecureStoreError::InvalidProviderCredential,
        SecureStoreError::ProviderCredentialNotFound,
        SecureStoreError::CredentialAccessDenied,
        SecureStoreError::CredentialIdentityMismatch,
        SecureStoreError::CredentialAclMigrationRequired,
        SecureStoreError::CorruptProviderCredential,
        SecureStoreError::ProviderCredentialOperationFailed,
        SecureStoreError::CredentialEnrollmentIncomplete,
        SecureStoreError::CredentialMigrationIncomplete,
        SecureStoreError::ProviderCredentialSourceRevisionUnavailable,
        SecureStoreError::ProviderJournalKeyGenerationFailed,
    ] {
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(marker));
        assert!(!rendered.contains('/'));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
#[test]
fn unsupported_platform_has_no_plaintext_fallback() {
    use runne_secure_store::{NativeProviderCredentialStore, StubStore};

    let store = NativeProviderCredentialStore::new();
    let executable = controlled_executable();
    assert_eq!(
        store
            .provider_credential_status(ProviderCredentialId::OpenAi, &executable.access)
            .unwrap(),
        ProviderCredentialStatus::Unsupported
    );
    assert!(matches!(store, StubStore { .. }));
}

#[path = "provider_credential/versioned.rs"]
mod versioned;
