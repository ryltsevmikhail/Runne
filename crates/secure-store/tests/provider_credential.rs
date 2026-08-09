use gocode_secure_store::{
    MAX_PROVIDER_CREDENTIAL_BYTES, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialMaterial, ProviderCredentialSource, ProviderCredentialSourceRevision,
    ProviderCredentialStatus, ProviderCredentialStore, SecureStoreError,
};
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
    assert_eq!(
        ProviderCredentialSourceRevision::new([0; 16]).unwrap_err(),
        SecureStoreError::InvalidProviderCredential
    );
    let source = ProviderCredentialSource::new(
        ProviderCredentialMaterial::new(marker).unwrap(),
        ProviderCredentialSourceRevision::new([0x71; 16]).unwrap(),
    );
    let rendered = format!("{source:?} {:?}", source.revision());
    assert!(!rendered.contains("provider-secret-marker-7f3c"));
    assert!(!rendered.contains("71717171"));
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
    assert_eq!(
        store
            .load_provider_credential_source(ProviderCredentialId::OpenAi, &executable.access)
            .unwrap_err(),
        SecureStoreError::ProviderCredentialSourceRevisionUnavailable
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
        SecureStoreError::ProviderCredentialSourceRevisionUnavailable,
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

#[path = "provider_credential/versioned.rs"]
mod versioned;
