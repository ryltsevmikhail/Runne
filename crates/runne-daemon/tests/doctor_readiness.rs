//! DP1 readiness checks for `runned doctor` (D1.5): read-only projection of
//! the runtime database. Fresh install warns, a real daemon-created database
//! passes, a corrupted one fails — and readiness never changes the exit code.

use std::process::{Command, Output};

fn isolated() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn doctor_command(dir: &tempfile::TempDir) -> Command {
    let root = dir.path();
    let mut command = Command::new(env!("CARGO_BIN_EXE_runned"));
    command
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("HOME", root.join("home"));
    command
}

fn run_doctor_json(dir: &tempfile::TempDir) -> (serde_json::Value, Output) {
    let output = doctor_command(dir)
        .args(["doctor", "--format", "json"])
        .output()
        .expect("run doctor");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("one JSON object");
    (value, output)
}

fn check<'a>(value: &'a serde_json::Value, id: &str) -> &'a str {
    value["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|check| check["id"] == id)
        .unwrap_or_else(|| panic!("check {id} present"))["status"]
        .as_str()
        .expect("check status")
}

#[test]
fn fresh_runtime_warns_readiness_without_failing_execution() {
    let dir = isolated();
    let (value, output) = run_doctor_json(&dir);
    assert_eq!(check(&value, "readiness.db_integrity"), "warn");
    assert_eq!(check(&value, "readiness.terminal_outbox"), "warn");
    assert_eq!(check(&value, "readiness.uncertain_attempts"), "warn");
    assert_eq!(check(&value, "readiness.text_only_path"), "pass");
    assert_eq!(check(&value, "readiness.tools_disabled"), "pass");
    assert_eq!(value["executionReady"], true, "readiness is advisory");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn real_daemon_database_passes_readiness_checks() {
    let dir = isolated();
    let runtime_dir = dir.path().join("runtime");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut defaults = runne_daemon::config::BuiltInDefaults::new(&runtime_dir);
        "127.0.0.1:0".clone_into(&mut defaults.http_bind);
        let config = runne_daemon::config::ConfigurationSnapshot::from_defaults(&defaults);
        let application = Box::pin(runne_daemon::application::DaemonApplication::start(&config))
            .await
            .expect("start daemon");
        drop(application);
    });

    let (value, output) = run_doctor_json(&dir);
    assert_eq!(check(&value, "readiness.db_integrity"), "pass");
    assert_eq!(check(&value, "readiness.terminal_outbox"), "pass");
    assert_eq!(check(&value, "readiness.uncertain_attempts"), "pass");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn corrupted_database_fails_integrity_advisory_only() {
    let dir = isolated();
    let runtime_dir = dir.path().join("runtime");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut defaults = runne_daemon::config::BuiltInDefaults::new(&runtime_dir);
        "127.0.0.1:0".clone_into(&mut defaults.http_bind);
        let config = runne_daemon::config::ConfigurationSnapshot::from_defaults(&defaults);
        let application = Box::pin(runne_daemon::application::DaemonApplication::start(&config))
            .await
            .expect("start daemon");
        drop(application);
    });

    let database = runtime_dir.join("runne-daemon").join("event-log.db");
    let mut bytes = std::fs::read(&database).unwrap();
    // Clobber the file header magic: quick_check then fails closed instead of
    // silently skipping free pages.
    bytes[..16].fill(0xDE);
    std::fs::write(&database, bytes).unwrap();

    let (value, output) = run_doctor_json(&dir);
    assert_eq!(check(&value, "readiness.db_integrity"), "fail");
    assert_eq!(
        value["executionReady"], true,
        "readiness stays advisory for execution readiness"
    );
    assert_eq!(output.status.code(), Some(0));
}
