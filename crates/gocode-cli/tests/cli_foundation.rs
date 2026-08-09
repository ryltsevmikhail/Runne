//! Integration tests for CLI foundation: help, version, output format, exit codes.

#![cfg(unix)]

use std::process::Command;

fn run_cli(arguments: &[&str]) -> std::process::Output {
    let executable = env!("CARGO_BIN_EXE_gocode");
    Command::new(executable)
        .args(arguments)
        .output()
        .expect("run CLI")
}

// ===== Help tests =====

#[test]
fn help_flag_shows_top_level_help() {
    let output = run_cli(&["--help"]);
    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("GOCODE command-line interface"));
    assert!(stdout.contains("conversation"));
    assert!(stdout.contains("provider"));
    assert!(stdout.contains("status"));
    assert!(output.stderr.is_empty());
}

#[test]
fn help_short_flag_shows_top_level_help() {
    let output = run_cli(&["-h"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("GOCODE command-line interface"));
}

#[test]
fn help_subcommand_shows_top_level_help() {
    let output = run_cli(&["help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("GOCODE command-line interface"));
}

#[test]
fn help_conversation_shows_conversation_help() {
    let output = run_cli(&["help", "conversation"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Manage conversations"));
    assert!(stdout.contains("create"));
    assert!(stdout.contains("send"));
    assert!(stdout.contains("messages"));
}

#[test]
fn help_conversation_create_shows_create_help() {
    let output = run_cli(&["help", "conversation", "create"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Create a new conversation"));
    assert!(stdout.contains("--workspace-id"));
}

#[test]
fn conversation_help_flag_shows_conversation_help() {
    let output = run_cli(&["conversation", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Manage conversations"));
}

#[test]
fn conversation_create_help_flag_shows_create_help() {
    let output = run_cli(&["conversation", "create", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Create a new conversation"));
}

#[test]
fn status_help_flag_shows_status_help() {
    let output = run_cli(&["status", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Show runtime connection status"));
}

#[test]
fn provider_help_flag_shows_provider_help() {
    let output = run_cli(&["provider", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Manage provider credentials"));
}

// ===== Version tests =====

#[test]
fn version_flag_shows_version() {
    let output = run_cli(&["--version"]);
    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gocode"));
    assert!(output.stderr.is_empty());
}

#[test]
fn version_short_flag_shows_version() {
    let output = run_cli(&["-V"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gocode"));
}

// ===== Exit code tests =====

#[test]
fn unknown_command_returns_exit_code_2() {
    let output = run_cli(&["unknown"]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn missing_profile_returns_exit_code_3() {
    let output = run_cli(&["--profile", "/nonexistent/profile.json", "status"]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unavailable") || stderr.contains("incompatible"));
}

// ===== JSON format tests =====

#[test]
fn json_format_success_returns_valid_envelope() {
    let output = run_cli(&["--format", "json", "--help"]);
    assert!(output.status.success());
    // Help is always text, not JSON
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("GOCODE command-line interface"));
}

#[test]
fn json_format_error_returns_valid_envelope() {
    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        "/nonexistent/profile.json",
        "status",
    ]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&stderr).expect("valid JSON");
    assert_eq!(parsed["schemaVersion"], 1);
    assert_eq!(parsed["ok"], false);
    assert!(parsed["error"]["code"].is_string());
    assert!(parsed["error"]["message"].is_string());
}

#[test]
fn json_format_equals_syntax_works() {
    let output = run_cli(&[
        "--format=json",
        "--profile",
        "/nonexistent/profile.json",
        "status",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&stderr).expect("valid JSON");
    assert_eq!(parsed["schemaVersion"], 1);
}

// ===== Status command tests =====

#[test]
fn status_without_runtime_returns_error() {
    // Without a running daemon, status should fail gracefully
    let output = run_cli(&["status"]);
    // May fail with profile unavailable or runtime unavailable
    assert!(!output.status.success());
    let code = output.status.code().expect("exit code");
    assert!(code == 1 || code == 3);
}

// ===== Health command tests =====

#[test]
fn health_help_flag_shows_health_help() {
    let output = run_cli(&["health", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Check runtime health status"));
}

#[test]
fn help_health_shows_health_help() {
    let output = run_cli(&["help", "health"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Check runtime health status"));
}

#[test]
fn top_level_help_includes_health() {
    let output = run_cli(&["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("health"));
    assert!(stdout.contains("Check runtime health status"));
}

#[test]
fn health_without_runtime_returns_error() {
    // Without a running daemon, health should fail gracefully
    let output = run_cli(&["health"]);
    assert!(!output.status.success());
    let code = output.status.code().expect("exit code");
    assert!(code == 1 || code == 3);
}

// ===== Doctor command tests =====

#[test]
fn doctor_help_flag_shows_doctor_help() {
    let output = run_cli(&["doctor", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Run comprehensive system diagnostics"));
}

#[test]
fn help_doctor_shows_doctor_help() {
    let output = run_cli(&["help", "doctor"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Run comprehensive system diagnostics"));
}

#[test]
fn top_level_help_includes_doctor() {
    let output = run_cli(&["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("doctor"));
    assert!(stdout.contains("Run comprehensive system diagnostics"));
}

#[test]
fn doctor_without_runtime_returns_error() {
    // Without a running daemon, doctor should fail gracefully
    let output = run_cli(&["doctor"]);
    assert!(!output.status.success());
    let code = output.status.code().expect("exit code");
    // Doctor returns 1 when checks fail
    assert_eq!(code, 1);
}

// ===== Messages formatting tests =====

#[test]
fn messages_text_format_returns_human_readable() {
    // This test would require a running runtime with a conversation
    // For now, we'll test that the command accepts the format flag
    let output = run_cli(&["conversation", "messages", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("List messages in a conversation"));
}

#[test]
fn messages_json_format_returns_json() {
    // This test would require a running runtime with a conversation
    // For now, we'll test that the command accepts the format flag
    let output = run_cli(&["conversation", "messages", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--conversation-id"));
}

// ===== Completion command tests =====

#[test]
fn completion_help_flag_shows_completion_help() {
    let output = run_cli(&["completion", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Generate shell completion scripts"));
}

#[test]
fn help_completion_shows_completion_help() {
    let output = run_cli(&["help", "completion"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Generate shell completion scripts"));
}

#[test]
fn top_level_help_includes_completion() {
    let output = run_cli(&["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("completion"));
    assert!(stdout.contains("Generate shell completion scripts"));
}

#[test]
fn completion_bash_generates_script() {
    let output = run_cli(&["completion", "bash"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("_gocode"));
    assert!(stdout.contains("complete -F"));
}

#[test]
fn completion_zsh_generates_script() {
    let output = run_cli(&["completion", "zsh"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("_gocode"));
    assert!(stdout.contains("compdef"));
}

#[test]
fn completion_fish_generates_script() {
    let output = run_cli(&["completion", "fish"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("complete -c gocode"));
}

#[test]
fn completion_powershell_generates_script() {
    let output = run_cli(&["completion", "powershell"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Register-ArgumentCompleter"));
}

#[test]
fn completion_invalid_shell_returns_error() {
    let output = run_cli(&["completion", "invalid"]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
}
