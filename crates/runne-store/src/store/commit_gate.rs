//! Test-support-only handshake at the real durable commit boundary.
//!
//! Compiled exclusively under `test-support`; production builds contain no
//! hook and read no environment. When a test process arms
//! `RUNNE_TEST_COMMIT_GATE_COMMAND_ID`, the unit-of-work commit path writes
//! that marker after the matching TaskRunSubmitted transaction commits, then
//! blocks until `RUNNE_TEST_COMMIT_GATE_RELEASE` appears.
//!
//! The block is what makes the kill point deterministic: between marker and
//! release the daemon holds the committed transaction with the client
//! acknowledgement not yet even serialized, so a fault test can assert the
//! undelivered ACK and SIGKILL the exact owned child inside the
//! post-commit/pre-ACK window on every run.

#[cfg(feature = "test-support")]
pub(crate) fn note_durable_commit(command_id: &str) {
    use std::time::{Duration, Instant};
    let Some(target) = std::env::var("RUNNE_TEST_COMMIT_GATE_COMMAND_ID").ok() else {
        return;
    };
    if target != command_id {
        return;
    }
    let Some(path) = std::env::var_os("RUNNE_TEST_COMMIT_GATE_FILE") else {
        return;
    };
    let release = std::env::var_os("RUNNE_TEST_COMMIT_GATE_RELEASE");
    // Best-effort marker: the observing test owns existence checks; a write
    // failure must never turn a committed transaction into a command error.
    let _ = std::fs::write(&path, b"commit");
    let Some(release) = release else {
        return;
    };
    // Hold the daemon in the post-commit/pre-ACK state until the test
    // releases it. Bounded so an aborted test cannot hang a child forever.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !std::path::Path::new(&release).exists() {
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
