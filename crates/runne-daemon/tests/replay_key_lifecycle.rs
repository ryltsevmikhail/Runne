use runne_daemon::replay_key::ReplayIntegrityKeyManager;
use std::fs;
use tempfile::tempdir;

#[test]
fn replay_integrity_key_is_stable_owner_only_and_redacted() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("replay-integrity.key");
    let first = ReplayIntegrityKeyManager::load_or_provision(&path).unwrap();
    let second = ReplayIntegrityKeyManager::load_or_provision(&path).unwrap();

    assert_eq!(first.derive_hmac(b"cursor"), second.derive_hmac(b"cursor"));
    assert_eq!(fs::read(&path).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_ne!(first.derive_hmac(b"cursor"), [0; 32]);
}

#[cfg(target_os = "linux")]
#[test]
fn replay_integrity_key_rejects_symlink() {
    use std::os::unix::fs::symlink;
    let directory = tempdir().unwrap();
    let target = directory.path().join("target");
    fs::write(&target, [9_u8; 32]).unwrap();
    let link = directory.path().join("replay-integrity.key");
    symlink(&target, &link).unwrap();
    assert!(ReplayIntegrityKeyManager::load_or_provision(&link).is_err());
    assert_eq!(fs::read(target).unwrap(), [9_u8; 32]);
}

#[test]
fn replay_integrity_key_rejects_wrong_size_without_rewriting() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("replay-integrity.key");
    let malformed = vec![7_u8; 31];
    fs::write(&path, &malformed).unwrap();

    let error = match ReplayIntegrityKeyManager::load_or_provision(&path) {
        Ok(_) => panic!("malformed replay key must fail"),
        Err(error) => error,
    };
    assert_eq!(fs::read(&path).unwrap(), malformed);
    assert!(!error.to_string().contains("070707"));
}
