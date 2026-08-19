use runne_daemon::config;

#[cfg(unix)]
use std::io::Write;

#[cfg(unix)]
fn temp_toml(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let mut file = std::fs::File::create(&path).unwrap();
    write!(file, "{content}").unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    (directory, path)
}

#[cfg(unix)]
#[test]
fn reject_unknown_key() {
    let (_directory, path) = temp_toml(
        r#"
schema_version = 2
bogus_field = 42
"#,
    );
    let error = config::load_config(Some(&path)).unwrap_err().to_string();
    assert!(
        error.contains("bogus_field") || error.contains("unknown"),
        "got: {error}"
    );
}

#[cfg(unix)]
#[test]
fn reject_duplicate_key() {
    let (_directory, path) = temp_toml(
        r#"
schema_version = 2
http_bind = "0.0.0.0:8080"
http_bind = "127.0.0.1:3000"
"#,
    );
    assert!(config::load_config(Some(&path)).is_err());
}

#[cfg(unix)]
#[test]
fn reject_wrong_version() {
    let (_directory, path) = temp_toml("schema_version = 1\n");
    let error = config::load_config(Some(&path)).unwrap_err().to_string();
    assert!(error.contains("schema_version"), "got: {error}");
}

#[cfg(unix)]
#[test]
fn reject_wrong_type() {
    let (_directory, path) = temp_toml(
        r#"
schema_version = 2
max_in_flight = "not a number"
"#,
    );
    assert!(config::load_config(Some(&path)).is_err());
}

#[cfg(unix)]
#[test]
fn merge_applies_override() {
    use runne_daemon::config::Source;

    let (_directory, path) = temp_toml(
        r#"
schema_version = 2
http_bind = "0.0.0.0:9090"
max_in_flight = 50
"#,
    );
    let snapshot = config::load_config(Some(&path)).unwrap();
    assert_eq!(snapshot.http_bind, "0.0.0.0:9090");
    assert_eq!(snapshot.max_in_flight, 50);
    assert_eq!(snapshot.shutdown_timeout_ms, 10_000);
    assert_eq!(snapshot.schema_version, 2);
    assert_eq!(snapshot.provenance["http_bind"].source, Source::SystemFile);
    assert!(snapshot.provenance["http_bind"].path.is_some());
    assert_eq!(
        snapshot.provenance["max_in_flight"].source,
        Source::SystemFile
    );
    assert_eq!(
        snapshot.provenance["shutdown_timeout_ms"].source,
        Source::BuiltIn
    );
    assert!(snapshot.provenance["shutdown_timeout_ms"].path.is_none());
    assert_eq!(
        snapshot.provenance["schema_version"].source,
        Source::BuiltIn
    );
}

#[cfg(unix)]
#[test]
fn digest_differs_for_different_configs() {
    let (_first_directory, first_path) = temp_toml(
        r#"
schema_version = 2
http_bind = "0.0.0.0:8080"
"#,
    );
    let (_second_directory, second_path) = temp_toml(
        r#"
schema_version = 2
http_bind = "10.0.0.1:3000"
"#,
    );
    let first = config::load_config(Some(&first_path)).unwrap();
    let second = config::load_config(Some(&second_path)).unwrap();
    assert_ne!(first.digest, second.digest);
}

#[cfg(unix)]
#[test]
fn external_openai_activation_requires_the_released_non_secret_profile_tuple() {
    let (_directory, path) = temp_toml(
        r#"
schema_version = 2

[provider_activation]
mode = "openai_responses_text_v1"
profile_id = "runne-openai-responses-text/1"
profile_digest = "9e04ed0d3cdeb99279433f01dfd44b2b67af80c076c5a63f45437f9880bae27e"
"#,
    );
    let snapshot = config::load_config(Some(&path)).expect("exact owner config");
    assert_eq!(
        snapshot.provider_activation.binding().profile_id(),
        "runne-openai-responses-text/1"
    );
}

#[cfg(unix)]
#[test]
fn external_openai_activation_rejects_a_changed_profile_digest() {
    let (_directory, path) = temp_toml(
        r#"
schema_version = 2

[provider_activation]
mode = "openai_responses_text_v1"
profile_id = "runne-openai-responses-text/1"
profile_digest = "0000000000000000000000000000000000000000000000000000000000000000"
"#,
    );
    assert!(config::load_config(Some(&path)).is_err());
}

#[cfg(unix)]
#[test]
fn external_entry_source_selects_exact_openai_without_downgrade() {
    let (_directory, path) = temp_toml(
        "schema_version = 2\n[provider_activation]\nmode = \"openai_responses_text_v1\"\nprofile_id = \"runne-openai-responses-text/1\"\nprofile_digest = \"9e04ed0d3cdeb99279433f01dfd44b2b67af80c076c5a63f45437f9880bae27e\"\n",
    );
    let snapshot = config::load_external_config_at(&path).unwrap();
    assert!(snapshot.provider_activation.requires_openai_execution());
}

#[cfg(unix)]
#[test]
fn external_explicit_source_rejects_symlink_and_oversize() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.toml");
    std::fs::write(&target, "schema_version = 2\n").unwrap();
    std::fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let link = directory.path().join("link.toml");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(config::load_config(Some(&link)).is_err());

    let oversized = directory.path().join("oversized.toml");
    std::fs::write(&oversized, "x".repeat(16 * 1024 + 1)).unwrap();
    std::fs::set_permissions(
        &oversized,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    assert!(config::load_config(Some(&oversized)).is_err());
}

#[cfg(unix)]
#[test]
fn bounded_reader_rejects_content_larger_than_verified_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("large.toml");
    std::fs::write(&path, "#".repeat(16 * 1024 + 1)).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    assert!(config::load_external_config_at(&path).is_err());
}

#[cfg(not(unix))]
#[test]
fn explicit_config_fails_closed_without_secure_file_validation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "schema_version = 2\n").unwrap();
    let error = config::load_config(Some(&path)).unwrap_err().to_string();
    assert!(error.contains("external config validation is unsupported"));
}
