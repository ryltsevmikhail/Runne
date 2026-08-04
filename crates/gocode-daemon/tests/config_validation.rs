//! Integration tests for daemon configuration (Phase 4, Task 1).
//!
//! Covers defaults, platform-independent failure behavior, and deterministic
//! digests. Secure explicit-file semantics live in the adjacent module.

use gocode_daemon::config;
use std::path::PathBuf;

#[path = "config_validation/explicit_file.rs"]
mod explicit_file;

#[test]
fn defaults_valid() {
    let snapshot = config::load_config(None).unwrap();
    assert_eq!(snapshot.schema_version, 2);
    assert_eq!(snapshot.http_bind, "127.0.0.1:3000");
    assert_eq!(snapshot.max_in_flight, 100);
    assert_eq!(snapshot.shutdown_timeout_ms, 10_000);
    assert!(snapshot.db_path.contains("gocode-daemon"));
    assert!(snapshot.replay_integrity_key_path.contains("gocode-daemon"));
    assert!(!snapshot.digest.is_empty());
    assert!(snapshot.digest.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn digest_deterministic() {
    let first = config::load_config(None).unwrap();
    let second = config::load_config(None).unwrap();
    assert_eq!(first.digest, second.digest, "digests must be deterministic");
}

#[test]
fn missing_explicit_file_fails_closed() {
    let non_existent = PathBuf::from("/tmp/gocode-daemon-nonexistent-42ab9c.toml");
    assert!(!non_existent.exists());
    assert!(config::load_config(Some(&non_existent)).is_err());
}

#[test]
fn fixed_external_source_defaults_only_when_absent_and_rejects_broken_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let absent = directory.path().join("absent.toml");
    assert!(
        !config::load_external_config_at(&absent)
            .unwrap()
            .provider_activation
            .requires_openai_execution()
    );
    #[cfg(unix)]
    {
        let broken = directory.path().join("broken.toml");
        std::os::unix::fs::symlink(directory.path().join("missing-target"), &broken).unwrap();
        assert!(config::load_external_config_at(&broken).is_err());
    }
}
