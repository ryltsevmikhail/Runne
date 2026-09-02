const LOCAL_TEST_KEYCHAIN_PASSWORD: &[u8] = b"slice-e-disposable";

fn local_test_keychain_password() -> Result<&'static [u8], KeychainAclError> {
    use std::os::unix::fs::MetadataExt as _;

    if std::env::var_os("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return Err(KeychainAclError::AccessDenied);
    }
    let home = std::path::PathBuf::from(
        std::env::var_os("HOME").ok_or(KeychainAclError::AccessDenied)?,
    );
    let selected = std::path::PathBuf::from(
        std::env::var_os("RUNNE_CI_MACOS_KEYCHAIN")
            .ok_or(KeychainAclError::AccessDenied)?,
    );
    let expected = home.join("Library/Keychains/runne-ci.keychain-db");
    let root = home.parent().ok_or(KeychainAclError::AccessDenied)?;
    let fixture_root = std::path::PathBuf::from(
        std::env::var_os("RUNNE_SLICE_E_FIXTURE_ROOT")
            .ok_or(KeychainAclError::AccessDenied)?,
    );
    if selected != expected
        || fixture_root != root
        || std::fs::canonicalize(&fixture_root).ok().as_deref() != Some(root)
        || std::fs::canonicalize(&selected).ok().as_deref() != Some(selected.as_path())
        || std::fs::canonicalize(&home).ok().as_deref() != Some(home.as_path())
        || std::fs::canonicalize(root).ok().as_deref() != Some(root)
        || !root
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().starts_with(b"runne-slice-e-"))
    {
        return Err(KeychainAclError::AccessDenied);
    }
    for path in [root, home.as_path()] {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| KeychainAclError::AccessDenied)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(KeychainAclError::AccessDenied);
        }
    }
    let metadata =
        std::fs::symlink_metadata(&selected).map_err(|_| KeychainAclError::AccessDenied)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(KeychainAclError::AccessDenied);
    }
    Ok(LOCAL_TEST_KEYCHAIN_PASSWORD)
}
