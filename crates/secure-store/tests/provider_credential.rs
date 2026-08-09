use gocode_provider::{CredentialVersionRef, ProviderId};
use gocode_secure_store::{
    MAX_PROVIDER_CREDENTIAL_BYTES, NativeProviderCredentialVersionStore,
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialMaterial,
    ProviderCredentialStatus, ProviderCredentialStore, SecureStoreError,
};
use std::{collections::HashMap, sync::Mutex};
struct ControlledExecutable {
    access: ProviderCredentialAccessPolicy,
}

fn controlled_executable() -> ControlledExecutable {
    let executable = std::env::current_exe().expect("current test executable");
    let access = ProviderCredentialAccessPolicy::new(&executable, &executable)
        .expect("controlled executable access policy");
    ControlledExecutable { access }
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
fn credential_material_is_bounded_single_line_and_redacted() {
    for invalid in [
        Vec::new(),
        vec![b'x'; MAX_PROVIDER_CREDENTIAL_BYTES + 1],
        b"first\nsecond".to_vec(),
        b"first\rsecond".to_vec(),
        b"prefix\0suffix".to_vec(),
    ] {
        assert_eq!(
            ProviderCredentialMaterial::new(invalid).unwrap_err(),
            SecureStoreError::InvalidProviderCredential
        );
    }

    let marker = b"provider-secret-marker-7f3c".to_vec();
    let credential = ProviderCredentialMaterial::new(marker.clone()).unwrap();
    assert_eq!(credential.with_bytes(<[u8]>::to_vec), marker);
    let debug = format!("{credential:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("provider-secret-marker-7f3c"));

    let maximum = ProviderCredentialMaterial::new(vec![b'x'; MAX_PROVIDER_CREDENTIAL_BYTES])
        .expect("exact maximum is accepted");
    assert_eq!(
        maximum.with_bytes(<[u8]>::len),
        MAX_PROVIDER_CREDENTIAL_BYTES
    );
}

#[test]
fn provider_identity_and_status_vocabulary_are_exact() {
    assert_eq!(ProviderCredentialId::OpenAi.account(), "openai");
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
        SecureStoreError::ProviderJournalKeyGenerationFailed,
    ] {
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(marker));
        assert!(!rendered.contains('/'));
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unsupported_platform_has_no_plaintext_fallback() {
    use gocode_secure_store::{NativeProviderCredentialStore, StubStore};

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

#[derive(Default)]
struct OpaqueVersionFixture(Mutex<HashMap<CredentialVersionRef, Vec<u8>>>);

impl NativeProviderCredentialVersionStore for OpaqueVersionFixture {
    fn create_version(
        &self,
        reference: CredentialVersionRef,
        credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let incoming = credential.with_bytes(<[u8]>::to_vec);
        let mut values = self.0.lock().unwrap();
        let result = match values.get(&reference) {
            Some(existing) if existing == &incoming => Ok(()),
            Some(_) => Err(SecureStoreError::ProviderCredentialOperationFailed),
            None => {
                values.insert(reference, incoming);
                Ok(())
            }
        };
        drop(values);
        result
    }

    fn load_version(
        &self,
        reference: CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.0
            .lock()
            .unwrap()
            .get(&reference)
            .cloned()
            .ok_or(SecureStoreError::ProviderCredentialNotFound)
            .and_then(ProviderCredentialMaterial::new)
    }

    fn delete_version(&self, reference: CredentialVersionRef) -> Result<(), SecureStoreError> {
        self.0.lock().unwrap().remove(&reference);
        Ok(())
    }
}

#[test]
fn opaque_version_operations_never_expose_secret_bytes() {
    let fixture = OpaqueVersionFixture::default();
    let reference = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 7).unwrap();
    let secret = b"opaque-fixture-secret-62cf".to_vec();
    let material = ProviderCredentialMaterial::new(secret.clone()).unwrap();
    let current = std::env::current_exe().unwrap();
    let access = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();

    fixture
        .create_version(reference.clone(), &material, &access)
        .unwrap();
    fixture
        .create_version(reference.clone(), &material, &access)
        .unwrap();
    let loaded = fixture.load_version(reference.clone(), &access).unwrap();

    assert_eq!(loaded.with_bytes(<[u8]>::to_vec), secret);
    for rendered in [
        format!("{reference:?}"),
        format!("{material:?}"),
        format!("{loaded:?}"),
    ] {
        assert!(!rendered.contains("opaque-fixture-secret-62cf"));
    }
    fixture.delete_version(reference.clone()).unwrap();
    fixture.delete_version(reference.clone()).unwrap();
    assert_eq!(
        fixture.load_version(reference, &access).unwrap_err(),
        SecureStoreError::ProviderCredentialNotFound
    );
}
