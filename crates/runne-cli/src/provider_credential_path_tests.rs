#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
#[test]
fn native_credential_resolver_requires_the_exact_packaged_daemon_reader() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir().expect("temporary package directory");
    let current = std::env::current_exe().expect("current CLI test executable");
    let writer = temporary.path().join(format!("runne{}", std::env::consts::EXE_SUFFIX));
    let reader = temporary
        .path()
        .join(format!("runned{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(&current, &writer).expect("copy packaged writer");
    std::fs::copy(&current, &reader).expect("copy packaged reader");
    #[cfg(unix)]
    for path in [&writer, &reader] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("mark packaged executable");
    }

    assert!(
        resolve_packaged_credential_access(&writer).is_ok()
    );

    std::fs::remove_file(&reader).expect("remove packaged reader");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&current, &reader).expect("substitute packaged reader");
        assert!(resolve_packaged_credential_access(&writer).is_err());
        std::fs::remove_file(&reader).expect("remove substituted reader");
    }
    let legacy_reader = temporary
        .path()
        .join(format!("runne-daemon{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(&current, &legacy_reader).expect("copy legacy reader");
    #[cfg(unix)]
    std::fs::set_permissions(&legacy_reader, std::fs::Permissions::from_mode(0o755))
        .expect("mark legacy executable");
    assert!(
        resolve_packaged_credential_access(&writer).is_err()
    );
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
#[test]
fn native_credential_backend_supports_desktop_targets() {
    assert!(native_credential_backend_supported());
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
#[test]
fn native_credential_backend_rejects_unsupported_targets() {
    assert!(!native_credential_backend_supported());
}
