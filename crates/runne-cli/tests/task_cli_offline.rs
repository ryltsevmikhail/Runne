#![cfg(unix)]

// Offline CLI tests for the read-only `task` command: the real binary runs
// against no daemon, covering help, usage, UUIDv7 validation, the absence of
// pagination flags, and profile error surfaces.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn run_cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_runne"))
        .args(arguments)
        .output()
        .expect("run CLI")
}

fn exit_code(output: &std::process::Output) -> i32 {
    output.status.code().expect("CLI exits with a code")
}

fn stdout_string(output: &std::process::Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout")
}

fn stderr_string(output: &std::process::Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("UTF-8 stderr")
}

fn parse_json_error_envelope(output: &std::process::Output, context: &str) -> serde_json::Value {
    let envelope: serde_json::Value =
        serde_json::from_str(&stderr_string(output)).expect("JSON error envelope");
    assert_eq!(envelope["schemaVersion"], 1, "{context}");
    assert_eq!(envelope["ok"], false, "{context}");
    envelope
}

#[test]
fn task_help_is_available_at_every_level() {
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["task", "--help"], "Inspect runtime task runs"),
        (vec!["task", "-h"], "Inspect runtime task runs"),
        (vec!["help", "task"], "Subcommands:"),
        (
            vec!["task", "list", "--help"],
            "runne [--profile PATH] task list",
        ),
        (vec!["help", "task", "list"], "pagination flags"),
        (vec!["task", "get", "--help"], "--task-run-id UUID"),
        (vec!["help", "task", "get"], "RFC 9562 UUIDv7"),
    ];
    for (arguments, needle) in cases {
        let output = run_cli(&arguments);
        assert!(
            output.status.success(),
            "{arguments:?} must succeed: {}",
            stderr_string(&output)
        );
        assert_eq!(exit_code(&output), 0, "{arguments:?}");
        assert!(
            output.stderr.is_empty(),
            "{arguments:?}: help goes to stdout"
        );
        let stdout = stdout_string(&output);
        assert!(stdout.contains(needle), "{arguments:?}: {stdout}");
    }
}

#[test]
fn top_level_help_lists_the_task_command() {
    for arguments in [vec!["--help"], vec!["help"]] {
        let output = run_cli(&arguments);
        assert!(output.status.success(), "{arguments:?}");
        let stdout = stdout_string(&output);
        assert!(
            stdout.contains("task             Inspect runtime task runs (read-only)"),
            "{arguments:?}: {stdout}"
        );
    }
}

#[test]
fn task_usage_errors_exit_with_code_two() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["task"],
        vec!["task", "bogus"],
        vec!["task", "list", "extra"],
        vec!["task", "list", "--limit", "5"],
        vec!["task", "list", "--offset", "2"],
        vec!["task", "list", "--cursor", "abc"],
        vec!["task", "list", "--profile", "/tmp/x.json"],
        vec!["task", "get"],
        vec!["task", "get", "--task-run-id"],
        vec!["task", "get", "--task-run-id", "not-a-uuid"],
        // Valid RFC 4122 UUID, but version 4: the CLI requires UUIDv7.
        vec![
            "task",
            "get",
            "--task-run-id",
            "5d3a7c8e-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
        ],
    ];
    for arguments in cases {
        let output = run_cli(&arguments);
        assert_eq!(exit_code(&output), 2, "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(
            stderr_string(&output).contains("Usage:"),
            "{arguments:?}: usage text expected"
        );
    }
}

#[test]
fn unknown_top_level_command_stays_unknown_command() {
    let output = run_cli(&["taskk"]);
    assert_eq!(exit_code(&output), 2);
    assert!(output.stdout.is_empty());
}

#[test]
fn json_mode_reports_stable_error_codes_for_task_usage() {
    let output = run_cli(&["--format", "json", "task", "bogus"]);
    assert_eq!(exit_code(&output), 2);
    assert!(output.stdout.is_empty());
    let envelope = parse_json_error_envelope(&output, "task bogus");
    assert_eq!(envelope["error"]["code"], "invalid_arguments");

    let output = run_cli(&["--format", "json", "task", "list", "--limit", "5"]);
    assert_eq!(exit_code(&output), 2);
    let envelope = parse_json_error_envelope(&output, "task list --limit");
    assert_eq!(envelope["error"]["code"], "invalid_arguments");

    let output = run_cli(&["--format", "json", "taskk"]);
    assert_eq!(exit_code(&output), 2);
    let envelope = parse_json_error_envelope(&output, "taskk");
    assert_eq!(envelope["error"]["code"], "unknown_command");
}

#[test]
fn missing_profile_is_profile_unavailable() {
    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        "/nonexistent/runne-task-test/profile.json",
        "task",
        "list",
    ]);
    assert_eq!(exit_code(&output), 3);
    assert!(output.stdout.is_empty());
    let envelope = parse_json_error_envelope(&output, "missing profile");
    assert_eq!(envelope["error"]["code"], "profile_unavailable");

    let output = run_cli(&[
        "--profile",
        "/nonexistent/runne-task-test/profile.json",
        "task",
        "list",
    ]);
    assert_eq!(exit_code(&output), 3);
    assert_eq!(
        stderr_string(&output),
        "local runtime profile is unavailable\n"
    );
}

#[test]
fn legacy_profile_is_incompatible_without_secret_disclosure() {
    let directory = tempfile::tempdir().expect("temp directory");
    let profile = directory.path().join("legacy-profile.json");
    let marker = "legacy-secret-marker";
    std::fs::write(
        &profile,
        format!(
            r#"{{"schemaVersion":1,"profileId":"runne-ui-client/1","schemaHash":"{marker}","endpoint":"http://127.0.0.1:9","tokenPath":"/tmp/{marker}"}}"#
        ),
    )
    .expect("write legacy profile");
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o600))
        .expect("secure profile");

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        profile.to_str().expect("profile path"),
        "task",
        "list",
    ]);

    assert_eq!(exit_code(&output), 3);
    assert!(output.stdout.is_empty());
    let envelope = parse_json_error_envelope(&output, "legacy profile");
    assert_eq!(envelope["error"]["code"], "profile_incompatible");
    let stderr = stderr_string(&output);
    assert!(!stderr.contains(marker));
    assert!(!stderr.contains(profile.to_str().expect("profile path")));
}
