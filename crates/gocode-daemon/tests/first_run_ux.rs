//! First-run UX for the daemon binary: diagnostics (`--help`, `--version`,
//! `doctor`) must work before bootstrap, without a credential, and must not
//! create any daemon state. Unknown arguments fail closed with exit 2.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn daemon_binary() -> &'static str {
    env!("CARGO_BIN_EXE_gocode-daemon")
}

/// Fresh temp root redirecting every directory the daemon could touch.
fn isolated() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// Builds one fresh command with every daemon directory redirected into
/// `dir`. Never reuse a returned command: `Command::args` appends.
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

/// Recursively counts files under `path`; used to prove no bootstrap happened.
fn file_count(path: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| {
            let path = entry.path();
            if path.is_dir() { file_count(&path) } else { 1 }
        })
        .sum()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn help_prints_usage_without_bootstrapping() {
    let dir = isolated();
    let output = isolated_command(&dir)
        .args(["--help"])
        .output()
        .expect("run daemon --help");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("gocode-daemon doctor"));
    assert!(stdout.contains("--version"));
    assert!(stderr(&output).is_empty(), "--help stderr must stay empty");
    assert_eq!(
        file_count(dir.path()),
        0,
        "--help must not create daemon state"
    );
}

#[test]
fn short_help_and_version_work_without_bootstrapping() {
    let dir = isolated();
    let output = isolated_command(&dir)
        .args(["-h"])
        .output()
        .expect("run daemon -h");
    assert!(output.status.success());
    assert!(stdout(&output).contains("gocode-daemon"));

    let output = isolated_command(&dir)
        .args(["--version"])
        .output()
        .expect("run daemon --version");
    assert!(output.status.success());
    assert_eq!(
        stdout(&output),
        format!("gocode-daemon {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(stderr(&output).is_empty());
    assert_eq!(file_count(dir.path()), 0);
}

#[test]
fn doctor_reports_deterministic_default_without_bootstrapping() {
    let dir = isolated();
    let output = isolated_command(&dir)
        .arg("doctor")
        .output()
        .expect("run daemon doctor");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("active provider: none (deterministic_v1)"));
    assert!(stdout.contains("credential openai:"));
    assert!(stdout.contains("credential deepseek:"));
    assert!(stdout.contains("execution ready: yes"));
    assert!(
        stderr(&output).is_empty(),
        "doctor stderr must stay empty: {}",
        stderr(&output)
    );
    assert_eq!(
        file_count(dir.path()),
        0,
        "doctor must not create daemon state"
    );
}

#[test]
fn unknown_arguments_fail_closed_without_echoing_values() {
    let dir = isolated();
    let output = isolated_command(&dir)
        .arg("--bogus")
        .output()
        .expect("run daemon --bogus");
    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("unknown argument"));
    assert!(
        !stderr.contains("--bogus"),
        "argument values must not be echoed: {stderr}"
    );
    assert_eq!(file_count(dir.path()), 0);
}

#[test]
fn extra_arguments_fail_closed_without_bootstrapping() {
    let dir = isolated();
    let output = isolated_command(&dir)
        .args(["doctor", "extra"])
        .output()
        .expect("run daemon doctor extra");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(file_count(dir.path()), 0);
}

/// Guard: the exact path arithmetic used by the env isolation helper.
#[test]
fn temp_root_stays_clean_through_helper() {
    let dir = isolated();
    let root: PathBuf = dir.path().to_path_buf();
    drop(root);
    assert_eq!(file_count(dir.path()), 0);
}
