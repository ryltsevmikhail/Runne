#[cfg(target_os = "macos")]
#[test]
fn native_legacy_import_rejects_reader_as_writer_before_keychain_access() {
    use crate::provider_credential::AuthorizedLegacySourceStore as _;
    use std::os::unix::fs::PermissionsExt as _;
    let current = current_writer_access();
    let directory = tempfile::tempdir().unwrap();
    let other = directory.path().join("other-writer");
    std::fs::copy("/usr/bin/true", &other).unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o500)).unwrap();
    let access = ProviderCredentialAccessPolicy::new(&other, &current.path).unwrap();
    assert!(access.validate_reader_current().is_ok());
    assert_eq!(access.validate_writer_current(), Err(SecureStoreError::CredentialIdentityMismatch));
    let native = crate::NativeProviderCredentialStore::new();
    assert_eq!(native.load_authorized_legacy_source(authorized_legacy_read(), &access).err(),
        Some(SecureStoreError::CredentialAccessDenied));
    drop(current);
}

#[cfg(target_os = "macos")]
#[test]
fn native_ordinary_source_read_still_rejects_writer_identity() {
    use std::os::unix::fs::PermissionsExt as _;
    let current = current_writer_access();
    let directory = tempfile::tempdir().unwrap();
    let other = directory.path().join("other-reader");
    std::fs::copy("/usr/bin/true", &other).unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o500)).unwrap();
    let access = ProviderCredentialAccessPolicy::new(&current.path, &other).unwrap();
    assert!(access.validate_writer_current().is_ok());
    let native = crate::NativeProviderCredentialStore::new();
    assert_eq!(native.load_provider_credential_source(ProviderCredentialId::OpenAi, &access).err(),
        Some(SecureStoreError::CredentialAccessDenied));
    drop(current);
}
