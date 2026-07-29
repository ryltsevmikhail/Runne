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
    (dir, path)
}

// ── 1. defaults_valid ───────────────────────────────────────────
#[test]
fn defaults_valid() {
    let snapshot = config::load_config(None).unwrap();
    assert_eq!(snapshot.schema_version, 1);
    assert_eq!(snapshot.http_bind, "127.0.0.1:3000");
    assert_eq!(snapshot.max_in_flight, 100);
    assert_eq!(snapshot.shutdown_timeout_ms, 10_000);
    // Paths should contain "gocode-daemon"
    assert!(snapshot.db_path.contains("gocode-daemon"));
    assert!(snapshot.token_path.contains("gocode-daemon"));
    // Digest must be non-empty hex
    assert!(!snapshot.digest.is_empty());
    assert!(snapshot.digest.chars().all(|c| c.is_ascii_hexdigit()));
}

// ── 2. reject_unknown_key ───────────────────────────────────────
#[test]
fn reject_unknown_key() {
    let (_dir, path) = temp_toml(
        r#"
schema_version = 1
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
schema_version = 1
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
schema_version = 2
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
schema_version = 1
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
schema_version = 1
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
    assert_eq!(snapshot.schema_version, 1);

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
fn missing_optional_file_ok() {
    let non_existent = PathBuf::from("/tmp/gocode-daemon-nonexistent-42ab9c.toml");
    assert!(!non_existent.exists());
    let snapshot = config::load_config(Some(&non_existent)).unwrap();
    assert!(!snapshot.digest.is_empty());
}

// ── 9. digest_differs_for_different_configs ─────────────────────
#[test]
fn digest_differs_for_different_configs() {
    let (_d1, p1) = temp_toml(
        r#"
schema_version = 1
http_bind = "0.0.0.0:8080"
"#,
    );
    let (_d2, p2) = temp_toml(
        r#"
schema_version = 1
http_bind = "10.0.0.1:3000"
"#,
    );
    let a = config::load_config(Some(&p1)).unwrap();
    let b = config::load_config(Some(&p2)).unwrap();
    assert_ne!(a.digest, b.digest);
}
