#![cfg(unix)]

use std::io::Write as _;
use std::process::{Command, Stdio};

#[test]
fn credential_set_rejects_forbidden_arguments_without_disclosing_them() {
    for arguments in [
        vec![
            "provider",
            "credential",
            "set",
            "--provider",
            "openai",
            "--value",
            "argv-secret-marker",
        ],
        vec![
            "provider",
            "credential",
            "set",
            "--provider",
            "openai",
            "--env",
            "ENV_SECRET_MARKER",
        ],
        vec![
            "provider",
            "credential",
            "set",
            "--provider",
            "openai",
            "--file",
            "/tmp/file-secret-marker",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_gocode"))
            .args(arguments)
            .output()
            .expect("run CLI");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("argv-secret-marker"));
        assert!(!stderr.contains("ENV_SECRET_MARKER"));
        assert!(!stderr.contains("file-secret-marker"));
    }
}

#[test]
fn credential_set_rejects_invalid_stdin_without_disclosure() {
    for input in [
        Vec::new(),
        b"nul\0marker".to_vec(),
        b"cr\rmarker".to_vec(),
        b"lf\nmarker".to_vec(),
        vec![b'x'; 4_097],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_gocode"))
            .args([
                "provider",
                "credential",
                "set",
                "--provider",
                "openai",
                "--stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start CLI");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(&input)
            .expect("write stdin");
        let output = child.wait_with_output().expect("wait CLI");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("marker"));
        assert!(!stderr.contains("xxxx"));
    }
}

#[test]
fn credential_cli_ignores_ambient_secret_environment_and_requires_stdin_flag() {
    let status = Command::new(env!("CARGO_BIN_EXE_gocode"))
        .args(["provider", "credential", "status", "--provider", "openai"])
        .env("OPENAI_API_KEY", "ambient-secret-marker")
        .output()
        .expect("run status");
    let status_output = format!(
        "{}{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(!status_output.contains("ambient-secret-marker"));
    assert!(
        status.stdout.is_empty()
            || status.stdout == b"configured\n"
            || status.stdout == b"missing\n"
            || status.stdout == b"unsupported\n"
    );

    let missing_stdin = Command::new(env!("CARGO_BIN_EXE_gocode"))
        .args(["provider", "credential", "set", "--provider", "openai"])
        .output()
        .expect("run set without stdin flag");
    assert!(!missing_stdin.status.success());
    assert!(missing_stdin.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&missing_stdin.stderr).contains("ambient-secret-marker"));
}

#[test]
fn credential_set_accepts_exact_4096_bytes_before_backend_resolution() {
    let input = vec![b'x'; 4_096];
    let mut child = Command::new(env!("CARGO_BIN_EXE_gocode"))
        .args([
            "provider",
            "credential",
            "set",
            "--provider",
            "openai",
            "--stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start CLI");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&input)
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait CLI");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("input is invalid"));
    assert!(!stderr.contains("xxxx"));
    assert!(
        output.stdout.is_empty()
            || output.stdout == b"configured\n"
            || output.stdout == b"unsupported\n"
    );
}
