use super::*;
#[test]
fn scoped_native_store_rejects_legacy_accounts_and_zero_authority() {
    let (_, native) = runne_provider::CredentialAuthorityPair::new().split();
    let scoped = NativeKeyringStore::new_cli_host_versioned(native.clone(), [1; 16]);
    assert_eq!(
        scoped.delete_provider_credential(ProviderCredentialId::DeepSeek),
        Err(SecureStoreError::CredentialAccessDenied)
    );
    let invalid = NativeKeyringStore::new_cli_host_versioned(native, [0; 16]);
    let reference =
        CredentialVersionRef::new(runne_provider::ProviderId::new("deepseek").unwrap(), 1).unwrap();
    assert_eq!(
        invalid.namespaced_version_key(&reference),
        Err(SecureStoreError::CredentialAccessDenied)
    );
}
#[test]
fn cli_runtime_namespaces_cannot_alias_each_other_or_desktop() {
    let (_, native) = runne_provider::CredentialAuthorityPair::new().split();
    let first = NativeKeyringStore::new_cli_host_versioned(native.clone(), [1; 16]);
    let second = NativeKeyringStore::new_cli_host_versioned(native, [2; 16]);
    let reference =
        CredentialVersionRef::new(runne_provider::ProviderId::new("deepseek").unwrap(), 1).unwrap();
    let first_key = first.namespaced_version_key(&reference).unwrap();
    assert_ne!(
        first_key,
        second.namespaced_version_key(&reference).unwrap()
    );
    assert_ne!(first_key, version_key(&reference).unwrap());
}
