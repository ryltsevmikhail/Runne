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
