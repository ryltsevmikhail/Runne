//! Redaction regression for `runned doctor` (slice B): the report must carry
//! no config location and no config content on the real binary path, while
//! failure causes stay distinguishable through stable `[config.*]` ids.
//!
//! Every fixture is synthetic and lives in an isolated temp root; the daemon
//! runs against redirected `XDG_CONFIG_HOME`/`HOME`/`XDG_RUNTIME_DIR` (same
//! isolation pattern as `first_run_ux.rs`). Unix permission fixtures are
//! `#[cfg(unix)]`.

use std::path::PathBuf;
use std::process::{Command, Output};

const TOKEN_CANARY: &str = "sk-synthetic-abc123";
const FIELD_CANARY: &str = "synthetic_not_a_token";

fn daemon_binary() -> &'static str {
    env!("CARGO_BIN_EXE_runned")
}

/// Fresh temp root redirecting every directory the daemon could touch.
fn isolated() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn isolated_command(dir: &tempfile::TempDir) -> Command {
    let root = dir.path();
    let mut command = Command::new(daemon_binary());
    command
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("HOME", root.join("home"))
        .env("LOCALAPPDATA", root.join("localappdata"))
        .env("APPDATA", root.join("appdata"));
    command
}

/// The external config location the daemon resolves inside the sandbox.
fn external_config_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path()
        .join("config")
        .join("runne-daemon")
        .join("config.toml")
}

fn write_config(dir: &tempfile::TempDir, contents: &str, mode: u32) {
    let path = external_config_path(dir);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, contents).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode)).unwrap();
    #[cfg(not(unix))]
    let _ = mode;
}

fn run_doctor(dir: &tempfile::TempDir) -> Output {
    isolated_command(dir)
        .arg("doctor")
        .output()
        .expect("run daemon doctor")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Common invariants: stderr stays empty, no doubled prefix, the sandbox path
/// and both canaries never reach stdout.
fn assert_common_redaction(dir: &tempfile::TempDir, output: &Output) {
    let out = stdout(output);
    let root = dir.path().to_str().unwrap();
    assert!(stderr(output).is_empty(), "stderr: {}", stderr(output));
    assert!(!out.contains("config error: config error:"), "{out}");
    assert!(!out.contains(root), "sandbox path leaked: {out}");
    assert!(!out.contains(TOKEN_CANARY), "token canary leaked: {out}");
    assert!(!out.contains(FIELD_CANARY), "field canary leaked: {out}");
}

#[test]
fn missing_config_stays_exit_zero_without_the_location() {
    let dir = isolated();
    let output = run_doctor(&dir);
    assert!(output.status.success());
    let out = stdout(&output);
    assert!(out.contains("[config.absent]"), "{out}");
    assert!(out.contains("execution ready: yes"));
    assert_common_redaction(&dir, &output);
}

#[cfg(unix)]
#[test]
fn invalid_toml_content_is_withheld_behind_the_parse_id() {
    let dir = isolated();
    write_config(
        &dir,
        &format!("schema_version = 2\n{FIELD_CANARY} = \"{TOKEN_CANARY}\"\n"),
        0o600,
    );
    let output = run_doctor(&dir);
    assert_eq!(output.status.code(), Some(1));
    let out = stdout(&output);
    assert!(out.contains("[config.parse]"), "{out}");
    assert!(out.contains("execution ready: no"));
    assert!(!out.contains("line 2"), "toml snippet leaked: {out}");
    assert_common_redaction(&dir, &output);
}

#[cfg(unix)]
#[test]
fn world_readable_config_reports_only_the_owner_private_id() {
    let dir = isolated();
    write_config(&dir, "schema_version = 2\n", 0o644);
    let output = run_doctor(&dir);
    assert_eq!(output.status.code(), Some(1));
    let out = stdout(&output);
    assert!(out.contains("[config.not_owner_private]"), "{out}");
    assert_common_redaction(&dir, &output);
}

#[cfg(unix)]
#[test]
fn unsupported_schema_version_hides_the_owner_value() {
    let dir = isolated();
    write_config(&dir, "schema_version = 3\n", 0o600);
    let output = run_doctor(&dir);
    assert_eq!(output.status.code(), Some(1));
    let out = stdout(&output);
    assert!(out.contains("[config.schema_version]"), "{out}");
    assert!(!out.contains("got 3"), "schema value leaked: {out}");
    assert_common_redaction(&dir, &output);
}

#[cfg(unix)]
#[test]
fn broken_symlink_reports_only_the_io_access_kind() {
    let dir = isolated();
    let path = external_config_path(&dir);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(dir.path().join("missing-target.toml"), &path).unwrap();
    let output = run_doctor(&dir);
    assert_eq!(output.status.code(), Some(1));
    let out = stdout(&output);
    assert!(out.contains("[config.io_access]"), "{out}");
    assert!(!out.contains("os error"), "raw io text leaked: {out}");
    assert_common_redaction(&dir, &output);
}

#[test]
fn failure_cause_ids_stay_pairwise_distinct() {
    let mut ids = vec![
        "config.absent",
        "config.parse",
        "config.not_owner_private",
        "config.schema_version",
        "config.io_access",
    ];
    ids.sort_unstable();
    let count = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), count, "integration ids must stay distinct");
}

mod format_parity {
    use super::*;

    /// Extracts `[id]` markers from the text rendering.
    fn text_ids(output: &str) -> Vec<String> {
        let mut ids = Vec::new();
        for line in output.lines() {
            let start = match line.rfind(" [") {
                Some(index) => index + 2,
                None => continue,
            };
            let end = line.rfind(']').expect("closed marker");
            ids.push(line[start..end].to_owned());
        }
        ids.sort();
        ids
    }

    fn run_doctor_format(dir: &tempfile::TempDir, format: &[&str]) -> Output {
        isolated_command(dir)
            .args(format)
            .output()
            .expect("run daemon doctor")
    }

    #[test]
    fn doctor_text_and_json_expose_the_same_check_ids_and_outcomes() {
        let dir = isolated();
        let text = run_doctor_format(&dir, &["doctor"]);
        let text_out = stdout(&text);

        let json = run_doctor_format(&dir, &["doctor", "--format", "json"]);
        let json_out = stdout(&json);
        let value: serde_json::Value = serde_json::from_str(json_out.trim())
            .expect("doctor --format json emits one JSON object");
        assert_eq!(value["schemaVersion"], 1);
        let checks = value["checks"].as_array().expect("checks array");
        let mut json_ids: Vec<String> = checks
            .iter()
            .map(|check| check["id"].as_str().expect("check id").to_owned())
            .collect();
        json_ids.sort();
        assert_eq!(json_ids, text_ids(&text_out), "identical check id sets");
        assert_eq!(value["executionReady"], true);
        assert_eq!(json.status.code(), text.status.code());
        assert!(!json_out.contains(dir.path().to_str().unwrap()));
        assert_common_redaction(&dir, &json);
    }

    #[test]
    fn doctor_json_reports_the_broken_config_like_text() {
        let dir = isolated();
        write_config(&dir, "schema_version = 999\n", 0o600);
        let text = run_doctor_format(&dir, &["doctor"]);
        let text_out = stdout(&text);
        assert!(text_out.contains("[config.schema_version]"), "{text_out}");

        let json = run_doctor_format(&dir, &["doctor", "--format", "json"]);
        let json_out = stdout(&json);
        let value: serde_json::Value = serde_json::from_str(json_out.trim()).unwrap();
        let ids: Vec<&str> = value["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|check| check["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"config.schema_version"), "{json_out}");
        assert_eq!(value["executionReady"], false);
        assert_eq!(json.status.code(), text.status.code());
        assert!(!json_out.contains("schema_version = 999"));
    }
}
