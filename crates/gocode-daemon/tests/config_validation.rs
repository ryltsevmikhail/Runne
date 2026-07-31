//! Integration tests for daemon configuration (Phase 4, Task 1).
//!
//! Covers: defaults, rejection of malformed TOML, merge semantics,
//! provenance tracking, and deterministic digest.

use gocode_daemon::config;
use std::io::Write;
use std::path::PathBuf;

// Helper: write a string to a temp file, return the path.
fn temp_toml(content: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut f = std::fs::File::create(&path).unwrap();
    write!(f, "{content}").unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    (dir, path)
}

// ── 1. defaults_valid ───────────────────────────────────────────
#[test]
fn defaults_valid() {
    let snapshot = config::load_config(None).unwrap();
    assert_eq!(snapshot.schema_version, 2);
    assert_eq!(snapshot.http_bind, "127.0.0.1:3000");
    assert_eq!(snapshot.max_in_flight, 100);
    assert_eq!(snapshot.shutdown_timeout_ms, 10_000);
    // Paths should contain "gocode-daemon"
    assert!(snapshot.db_path.contains("gocode-daemon"));
    assert!(snapshot.replay_integrity_key_path.contains("gocode-daemon"));
    // Digest must be non-empty hex
    assert!(!snapshot.digest.is_empty());
    assert!(snapshot.digest.chars().all(|c| c.is_ascii_hexdigit()));
}

// ── 2. reject_unknown_key ───────────────────────────────────────
#[test]
fn reject_unknown_key() {
    let (_dir, path) = temp_toml(
        r#"
schema_version = 2
bogus_field = 42
"#,
    );
    let result = config::load_config(Some(&path));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("bogus_field") || err.contains("unknown"),
        "got: {err}"
    );
}

// ── 3. reject_duplicate_key ─────────────────────────────────────
#[test]
fn reject_duplicate_key() {
    let (_dir, path) = temp_toml(
        r#"
schema_version = 2
http_bind = "0.0.0.0:8080"
http_bind = "127.0.0.1:3000"
"#,
    );
    let result = config::load_config(Some(&path));
    assert!(result.is_err());
}

// ── 4. reject_wrong_version ─────────────────────────────────────
#[test]
fn reject_wrong_version() {
    let (_dir, path) = temp_toml(
        r#"
schema_version = 1
"#,
    );
    let result = config::load_config(Some(&path));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("schema_version"), "got: {err}");
}

// ── 5. reject_wrong_type ────────────────────────────────────────
#[test]
fn reject_wrong_type() {
    let (_dir, path) = temp_toml(
        r#"
schema_version = 2
max_in_flight = "not a number"
"#,
    );
    let result = config::load_config(Some(&path));
    assert!(result.is_err());
}

// ── 6. merge_applies_override ───────────────────────────────────
#[test]
fn merge_applies_override() {
    use gocode_daemon::config::Source;

    let (_dir, path) = temp_toml(
        r#"
schema_version = 2
http_bind = "0.0.0.0:9090"
max_in_flight = 50
"#,
    );
    let snapshot = config::load_config(Some(&path)).unwrap();

    // Overridden values
    assert_eq!(snapshot.http_bind, "0.0.0.0:9090");
    assert_eq!(snapshot.max_in_flight, 50);

    // Default values still present for non-overridden fields
    assert_eq!(snapshot.shutdown_timeout_ms, 10_000);
    assert_eq!(snapshot.schema_version, 2);

    // Provenance: overridden fields → SystemFile
    let http_src = &snapshot.provenance["http_bind"];
    assert_eq!(http_src.source, Source::SystemFile);
    assert!(http_src.path.is_some());

    let inflight_src = &snapshot.provenance["max_in_flight"];
    assert_eq!(inflight_src.source, Source::SystemFile);

    // Provenance: default fields → BuiltIn
    let timeout_src = &snapshot.provenance["shutdown_timeout_ms"];
    assert_eq!(timeout_src.source, Source::BuiltIn);
    assert!(timeout_src.path.is_none());

    let schema_src = &snapshot.provenance["schema_version"];
    assert_eq!(schema_src.source, Source::BuiltIn);
}

// ── 7. digest_deterministic ─────────────────────────────────────
#[test]
fn digest_deterministic() {
    let a = config::load_config(None).unwrap();
    let b = config::load_config(None).unwrap();
    assert_eq!(a.digest, b.digest, "digests must be deterministic");
}

// ── 8. missing_optional_file_ok ─────────────────────────────────
#[test]
fn missing_explicit_file_fails_closed() {
    let non_existent = PathBuf::from("/tmp/gocode-daemon-nonexistent-42ab9c.toml");
    assert!(!non_existent.exists());
    assert!(config::load_config(Some(&non_existent)).is_err());
}

// ── 9. digest_differs_for_different_configs ─────────────────────
#[test]
fn digest_differs_for_different_configs() {
    let (_d1, p1) = temp_toml(
        r#"
schema_version = 2
http_bind = "0.0.0.0:8080"
"#,
    );
    let (_d2, p2) = temp_toml(
        r#"
schema_version = 2
http_bind = "10.0.0.1:3000"
"#,
    );
    let a = config::load_config(Some(&p1)).unwrap();
    let b = config::load_config(Some(&p2)).unwrap();
    assert_ne!(a.digest, b.digest);
}

#[test]
fn external_openai_activation_requires_the_released_non_secret_profile_tuple() {
    let (_dir, path) = temp_toml(
        r#"
schema_version = 2

[provider_activation]
mode = "openai_responses_text_v1"
profile_id = "gocode-openai-responses-text/1"
profile_digest = "d3e20934775d9d970350d16b78a1739885c08dd5d3e47b9307233d4dd0fbed80"
"#,
    );
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("owner-private config");
    let snapshot = config::load_config(Some(&path)).expect("exact owner config");
    assert_eq!(
        snapshot.provider_activation.binding().profile_id(),
        "gocode-openai-responses-text/1"
    );
}

#[test]
fn external_openai_activation_rejects_a_changed_profile_digest() {
    let (_dir, path) = temp_toml(
        r#"
schema_version = 2

[provider_activation]
mode = "openai_responses_text_v1"
profile_id = "gocode-openai-responses-text/1"
profile_digest = "0000000000000000000000000000000000000000000000000000000000000000"
"#,
    );
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("owner-private config");
    assert!(config::load_config(Some(&path)).is_err());
}

#[test]
fn external_entry_source_selects_exact_openai_without_downgrade() {
    let (_dir, path) = temp_toml(
        "schema_version = 2\n[provider_activation]\nmode = \"openai_responses_text_v1\"\nprofile_id = \"gocode-openai-responses-text/1\"\nprofile_digest = \"d3e20934775d9d970350d16b78a1739885c08dd5d3e47b9307233d4dd0fbed80\"\n",
    );
    let snapshot = config::load_external_config_at(&path).unwrap();
    assert!(snapshot.provider_activation.requires_openai_execution());
}

#[test]
fn external_explicit_source_rejects_symlink_and_oversize() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.toml");
    std::fs::write(&target, "schema_version = 2\n").unwrap();
    #[cfg(unix)]
    {
        std::fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(config::load_config(Some(&link)).is_err());
    }
    let oversized = dir.path().join("oversized.toml");
    std::fs::write(&oversized, "x".repeat(16 * 1024 + 1)).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(
        &oversized,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    assert!(config::load_config(Some(&oversized)).is_err());
}

#[test]
fn fixed_external_source_defaults_only_when_absent_and_rejects_broken_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("absent.toml");
    assert!(
        !config::load_external_config_at(&absent)
            .unwrap()
            .provider_activation
            .requires_openai_execution()
    );
    #[cfg(unix)]
    {
        let broken = dir.path().join("broken.toml");
        std::os::unix::fs::symlink(dir.path().join("missing-target"), &broken).unwrap();
        assert!(config::load_external_config_at(&broken).is_err());
    }
}

#[test]
fn bounded_reader_rejects_content_larger_than_verified_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large.toml");
    std::fs::write(&path, "#".repeat(16 * 1024 + 1)).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    assert!(config::load_external_config_at(&path).is_err());
}
