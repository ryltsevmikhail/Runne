#[cfg(target_os = "macos")]
#[test]
fn native_credential_resolver_requires_the_exact_packaged_daemon_reader() {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir().expect("temporary package directory");
    let current = std::env::current_exe().expect("current CLI test executable");
    let writer = temporary.path().join("gocode");
    let reader = temporary.path().join("gocode-daemon");
    std::fs::copy(&current, &writer).expect("copy packaged writer");
    std::fs::copy(&current, &reader).expect("copy packaged reader");
    for path in [&writer, &reader] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("mark packaged executable");
    }

    assert!(
        packaged_daemon_path(&writer)
            .and_then(|path| ProviderCredentialAccessPolicy::new(&writer, &path)
                .map_err(|_| CliError::CredentialOperation))
            .is_ok()
    );

    std::fs::remove_file(&reader).expect("remove packaged reader");
    let legacy_reader = temporary.path().join("gocoded");
    std::fs::copy(&current, &legacy_reader).expect("copy legacy reader");
    std::fs::set_permissions(&legacy_reader, std::fs::Permissions::from_mode(0o755))
        .expect("mark legacy executable");
    assert!(
        packaged_daemon_path(&writer)
            .and_then(|path| ProviderCredentialAccessPolicy::new(&writer, &path)
                .map_err(|_| CliError::CredentialOperation))
            .is_err()
    );
}
