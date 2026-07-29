use gocode_daemon::replay_key::ReplayIntegrityKeyManager;
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
    assert!(!format!("{first:?}").contains(&hex::encode(fs::read(&path).unwrap())));
}

#[test]
fn replay_integrity_key_rejects_wrong_size_without_rewriting() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("replay-integrity.key");
    let malformed = vec![7_u8; 31];
    fs::write(&path, &malformed).unwrap();

    let error = ReplayIntegrityKeyManager::load_or_provision(&path).unwrap_err();
    assert_eq!(fs::read(&path).unwrap(), malformed);
    assert!(!error.to_string().contains("070707"));
}
