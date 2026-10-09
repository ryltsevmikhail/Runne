//! Test-support-only handshake at the real durable commit boundary.
//!
//! Compiled exclusively under `test-support`; production builds contain no
//! hook and read no environment. When a test process arms
//! `RUNNE_TEST_COMMIT_GATE_COMMAND_ID` and the test creates the path named by
//! `RUNNE_TEST_COMMIT_GATE_ARM_FILE`, the unit-of-work commit path writes that
//! marker after the matching TaskRunSubmitted transaction commits, then blocks
//! until `RUNNE_TEST_COMMIT_GATE_RELEASE` appears.
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
    let Some(arm_file) = std::env::var_os("RUNNE_TEST_COMMIT_GATE_ARM_FILE") else {
        return;
    };
    if !std::path::Path::new(&arm_file).exists() {
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

/// Test-support-only kill-boundary handshake for the D1.6 real-kill matrix.
///
/// Same contract as [`note_durable_commit`], keyed by boundary name
/// (`RUNNE_TEST_KILL_BOUNDARY`) instead of command id: when the boundary is
/// armed (arm file exists), the daemon writes the marker file at the exact
/// boundary and blocks until the release file appears (bounded, so an aborted
/// test cannot hang a child forever).
#[cfg(feature = "test-support")]
pub(crate) fn note_kill_boundary(boundary: &str) {
    use std::time::{Duration, Instant};
    let Ok(target) = std::env::var("RUNNE_TEST_KILL_BOUNDARY") else {
        return;
    };
    if target != boundary {
        return;
    }
    let Some(arm_file) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_ARM") else {
        return;
    };
    if !std::path::Path::new(&arm_file).exists() {
        return;
    }
    let Some(marker) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_MARKER") else {
        return;
    };
    // Best-effort marker: the observing test owns existence checks.
    let _ = std::fs::write(&marker, boundary.as_bytes());
    let Some(release) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_RELEASE") else {
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    while !std::path::Path::new(&release).exists() {
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Test-support-only commit-gate dispatch for the TaskRun unit of work.
///
/// Submit commits are gated by the client command id; the terminal
/// TaskRunCompleted commit is gated only when a fault test pins an explicit
/// pre-known key via `RUNNE_TEST_COMMIT_GATE_TERMINAL_KEY`.
#[cfg(feature = "test-support")]
pub(crate) fn note_command_outcome(payload: &runne_application::ports::CommandCommit) {
    let key = match &payload.command_result {
        runne_application::commands::CommandOutcome::TaskRunSubmitted { .. } => {
            Some(payload.command_id.to_string())
        }
        // The terminal TaskRunCompleted commit carries an internal worker
        // command id no test can know, so the fault test pins this fixed key.
        runne_application::commands::CommandOutcome::TaskRunCompleted { .. } => {
            std::env::var("RUNNE_TEST_COMMIT_GATE_TERMINAL_KEY").ok()
        }
        _ => None,
    };
    if let Some(key) = key {
        note_durable_commit(&key);
    }
}
