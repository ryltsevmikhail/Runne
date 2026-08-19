#![cfg(unix)]

use runne_daemon_loopback_fixture::prepare_runtime_root;

#[test]
fn fixture_key_is_retained_under_a_private_file() {
    let root = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let first = prepare_runtime_root(root.path()).unwrap();
    let second = prepare_runtime_root(root.path()).unwrap();
    assert_eq!(first.bytes(), second.bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(first.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn fixture_key_rejects_a_permissive_runtime_root() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = prepare_runtime_root(root.path());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("permissive runtime root must be rejected"),
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}
