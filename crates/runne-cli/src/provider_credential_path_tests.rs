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

    assert!(resolve_packaged_credential_access(&writer).is_ok());

    std::fs::remove_file(&reader).expect("remove packaged reader");
    assert!(resolve_packaged_credential_access(&writer).is_err());
    #[cfg(unix)]
    {
        let sibling = temporary.path().join("same-directory-reader");
        std::fs::copy(&current, &sibling).expect("copy sibling reader");
        std::fs::set_permissions(&sibling, std::fs::Permissions::from_mode(0o755))
            .expect("mark sibling executable");
        std::os::unix::fs::symlink(&sibling, &reader).expect("substitute packaged reader");
        assert!(resolve_packaged_credential_access(&writer).is_err());
        std::fs::remove_file(&reader).expect("remove substituted reader");

        std::fs::hard_link(&sibling, &reader).expect("hard-link packaged reader");
        assert!(resolve_packaged_credential_access(&writer).is_err());
        std::fs::remove_file(&reader).expect("remove hard-linked reader");
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

#[cfg(unix)]
#[test]
fn packaged_resolver_detects_a_deterministic_reader_swap() {
    let temporary = tempfile::tempdir().expect("temporary package directory");
    let current = std::env::current_exe().expect("current CLI test executable");
    let writer = temporary.path().join(native_executable_name("runne"));
    let reader = temporary.path().join(native_executable_name("runned"));
    let replacement = temporary.path().join("replacement-reader");
    for path in [&writer, &reader, &replacement] {
        std::fs::copy(&current, path).expect("copy executable");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("mark executable");
    }

    let result = resolve_packaged_credential_access_with_hook(&writer, || {
        std::fs::rename(&replacement, &reader).expect("swap packaged reader");
    });
    assert!(result.is_err());
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
#[test]
fn production_resolver_fails_closed_without_authenticated_package_provenance() {
    let temporary = tempfile::tempdir().expect("temporary package directory");
    let current = std::env::current_exe().expect("current CLI test executable");
    let writer = temporary.path().join(native_executable_name("runne"));
    let reader = temporary.path().join(native_executable_name("runned"));
    std::fs::copy(&current, &writer).expect("copy writer");
    std::fs::copy(&current, &reader).expect("copy reader");
    #[cfg(unix)]
    for path in [&writer, &reader] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("mark executable");
    }

    assert!(resolve_authenticated_packaged_credential_access(&writer).is_err());
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
