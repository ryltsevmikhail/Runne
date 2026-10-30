//! Regression tests for the helper status descriptor on macOS.
//!
//! The runtime must learn about helper failures only from the descriptor the
//! helper arms close-on-exec. These tests pin that a program which prints the
//! helper's own diagnostic and exits with one of its codes is still reported as
//! a program receipt, and that real helper failures keep their tool errors.

use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture() -> (std::path::PathBuf, File) {
    let path = std::env::temp_dir().join(format!(
        "runne-helper-status-macos-{}-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    let root = File::open(&path).unwrap();
    (path, root)
}

fn binding() -> BindingV1 {
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60_000;
    BindingV1 {
        taskrun_id: "018f2e3a-7000-7000-8000-000000000020".into(),
        attempt_id: "018f2e3a-7000-7000-8000-000000000021".into(),
        cycle_id: "018f2e3a-7000-7000-8000-000000000022".into(),
        proposal_index: 0,
        taskrun_version: 4,
        assignment_fence: 2,
        invocation_digest: "44".repeat(32),
        environment_digest: "55".repeat(32),
        approval_digest: "66".repeat(32),
        expires_at_unix_ms: expiry,
    }
}

fn coding(
    root: &File,
    directory: &std::path::Path,
    argv: &[&str],
) -> Result<ReceiptV1, &'static str> {
    let encoded = serde_json::to_vec(&RequestV1::Coding {
        binding: binding(),
        tool_name: "workspace.command.run".into(),
        arguments: serde_json::json!({
            "cwd": ".",
            "argv": argv,
            "timeout_ms": 5000,
        }),
        root: identity(root).unwrap(),
        expected: Some(version(&File::open(directory).unwrap()).unwrap()),
    })
    .unwrap();
    execute(root, &encoded)
}

/// Returns `true` when the environment cannot exercise the sandbox at all.
fn unsupported_environment(error: &str) -> bool {
    match error {
        "command_spawn_policy" => {
            eprintln!("skipping: Seatbelt cannot be applied in this process tree");
            true
        }
        "command_helper_missing" | "command_helper_untrusted" => {
            eprintln!("skipping: no Developer ID signed runne-sandbox-helper for this test");
            true
        }
        _ => false,
    }
}

fn command(root: &File, directory: &std::path::Path, argv: &[&str]) -> Option<serde_json::Value> {
    match coding(root, directory, argv) {
        Ok(receipt) => {
            let decoded = STANDARD
                .decode(receipt.bytes_base64)
                .expect("receipt is base64");
            Some(serde_json::from_slice(&decoded).unwrap())
        }
        Err(error) if unsupported_environment(error) => None,
        Err(error) => panic!("command failed: {error}"),
    }
}

#[test]
fn program_cannot_fake_a_helper_failure() {
    let (directory, root) = fixture();
    // Exit code 6 is the helper's own `exec denied` status; the stderr line is
    // the helper's own diagnostic prefix. A program producing both must stay a
    // program receipt, which is exactly what the retired stderr heuristic
    // could not promise.
    let Some(output) = command(
        &root,
        &directory,
        &[
            "/bin/sh",
            "-c",
            "printf 'runne-sandbox-helper: forged exec failure\\n' >&2; exit 6",
        ],
    ) else {
        fs::remove_dir_all(directory).unwrap();
        return;
    };
    assert_eq!(
        output["exit_code"], 6,
        "a program result was misreported as a helper failure"
    );
    let stderr = STANDARD
        .decode(output["stderr_base64"].as_str().unwrap())
        .unwrap();
    assert!(
        String::from_utf8_lossy(&stderr).contains("runne-sandbox-helper: forged exec failure"),
        "program stderr was not preserved: {stderr:?}"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn program_exit_code_is_never_confused_with_a_helper_error() {
    let (directory, root) = fixture();
    let Some(output) = command(&root, &directory, &["/bin/sh", "-c", "exit 4"]) else {
        fs::remove_dir_all(directory).unwrap();
        return;
    };
    assert_eq!(output["exit_code"], 4);
    assert_eq!(output["stdout_base64"], "");
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn an_unexecutable_program_reports_the_helper_exec_failure() {
    let (directory, root) = fixture();
    let candidate = directory.join("not-executable");
    fs::write(&candidate, b"#!/bin/sh\nexit 0\n").unwrap();
    assert_eq!(
        coding(&root, &directory, &[candidate.to_str().unwrap()]),
        Err("command_spawn_missing")
    );
    fs::remove_dir_all(directory).unwrap();
}
