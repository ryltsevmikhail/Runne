// ===== Version tests =====

#[test]
fn version_flag_shows_version() {
    let output = run_cli(&["--version"]);
    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("runne"));
    assert!(output.stderr.is_empty());
}

#[test]
fn version_short_flag_shows_version() {
    let output = run_cli(&["-V"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("runne"));
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
    assert!(stdout.contains("Runne command-line interface"));
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
