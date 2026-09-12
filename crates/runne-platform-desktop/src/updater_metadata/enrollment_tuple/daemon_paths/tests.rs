use super::*;

fn staged_file(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    path
}

#[test]
fn retained_staged_daemon_rejects_digest_permissions_and_links() {
    let root = tempfile::tempdir().unwrap();
    let path = staged_file(root.path(), "daemon", b"signed fixture bytes");
    let digest: [u8; 32] = Sha256::digest(b"signed fixture bytes").into();
    assert!(RetainedStagedDaemon::open(&path, digest).is_ok());
    assert!(RetainedStagedDaemon::open(&path, [0; 32]).is_err());
    let link = root.path().join("alias");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(RetainedStagedDaemon::open(&link, digest).is_err());
    std::fs::hard_link(&path, root.path().join("hard-link")).unwrap();
    assert!(RetainedStagedDaemon::open(&path, digest).is_err());
    std::fs::remove_file(root.path().join("hard-link")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(RetainedStagedDaemon::open(&path, digest).is_err());
}

#[test]
fn retained_staged_daemon_detects_replacement_and_in_place_change() {
    let root = tempfile::tempdir().unwrap();
    let bytes = b"signed fixture bytes";
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let path = staged_file(root.path(), "daemon", bytes);
    let retained = RetainedStagedDaemon::open(&path, digest).unwrap();
    assert!(retained.matches_current().unwrap());
    let replacement = staged_file(root.path(), "replacement", bytes);
    std::fs::rename(replacement, &path).unwrap();
    assert!(!retained.matches_current().unwrap());
    let retained = RetainedStagedDaemon::open(&path, digest).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(&path, b"changed fixture data").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(!retained.matches_current().unwrap());
}

#[test]
fn authenticated_peer_outside_installed_desktop_package_is_rejected() {
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(NativeEnrollmentArtifactPathsV1::resolve_installed_from_authenticated_desktop_peer(&stream).is_err());
}
