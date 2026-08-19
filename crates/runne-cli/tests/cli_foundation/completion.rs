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
    assert!(stdout.contains("_runne"));
    assert!(stdout.contains("complete -F"));
}

#[test]
fn completion_zsh_generates_script() {
    let output = run_cli(&["completion", "zsh"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("_runne"));
    assert!(stdout.contains("compdef"));
}

#[test]
fn completion_fish_generates_script() {
    let output = run_cli(&["completion", "fish"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("complete -c runne"));
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
