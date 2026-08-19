// ===== Help tests =====

#[test]
fn help_flag_shows_top_level_help() {
    let output = run_cli(&["--help"]);
    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Runne command-line interface"));
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
    assert!(stdout.contains("Runne command-line interface"));
}

#[test]
fn help_subcommand_shows_top_level_help() {
    let output = run_cli(&["help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Runne command-line interface"));
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
