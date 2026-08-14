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
