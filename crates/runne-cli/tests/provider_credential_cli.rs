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
        let output = Command::new(env!("CARGO_BIN_EXE_runne"))
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
fn credential_set_rejects_without_reading_stdin_or_disclosing_it() {
    for input in [
        Vec::new(),
        b"nul\0marker".to_vec(),
        b"cr\rmarker".to_vec(),
        b"lf\nmarker".to_vec(),
        vec![b'x'; 4_097],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_runne"))
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
        assert_eq!(stderr, "provider credential backend is unsupported\n");
    }
}

#[test]
fn credential_cli_requires_stdin_flag() {
    let missing_stdin = Command::new(env!("CARGO_BIN_EXE_runne"))
        .args(["provider", "credential", "set", "--provider", "openai"])
        .output()
        .expect("run set without stdin flag");
    assert!(!missing_stdin.status.success());
    assert!(missing_stdin.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&missing_stdin.stderr).contains("ambient-secret-marker"));
}

#[test]
fn credential_help_and_completion_do_not_advertise_direct_secret_ingress() {
    let help = Command::new(env!("CARGO_BIN_EXE_runne"))
        .args(["help", "provider", "credential"])
        .output()
        .expect("show credential help");
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(!help.contains("--stdin"));
    assert!(help.contains("Unavailable direct credential enrollment"));

    for shell in ["fish", "zsh", "powershell"] {
        let output = Command::new(env!("CARGO_BIN_EXE_runne"))
            .args(["completion", shell])
            .output()
            .expect("generate completion");
        assert!(output.status.success(), "{shell}");
        let completion = String::from_utf8_lossy(&output.stdout);
        assert!(!completion.contains("Read from stdin"), "{shell}");
        assert!(!completion.contains("Store credential"), "{shell}");
        assert!(!completion.contains("Delete credential"), "{shell}");
    }
}
