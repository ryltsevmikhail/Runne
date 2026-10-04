use super::*;

#[test]
fn t1_protected_provider_http_and_runtime_client_replay() {
    run_t1_child(LocalWorkerMode::Provider);
}

#[test]
fn t1_protected_local_command_worker_only() {
    run_t1_child(LocalWorkerMode::Standard);
}

#[test]
fn t1_protected_local_command_crash_recovery() {
    run_t1_child(LocalWorkerMode::Crash);
}

#[test]
fn t1_protected_local_command_cancel_before_gate_release() {
    run_t1_child(LocalWorkerMode::CancelBeforeRelease);
}

#[test]
fn t1_protected_restart_with_missing_cancel_area_stays_unconfirmed() {
    run_t1_child(LocalWorkerMode::RestartAfterMissingArea);
}

#[test]
fn t1_protected_local_command_cancel_after_exit_proof() {
    run_t1_child(LocalWorkerMode::CancelAfterExit);
}

#[test]
fn t1_protected_local_command_completion_before_late_cancel() {
    run_t1_child(LocalWorkerMode::CompleteAfterExit);
}

#[test]
fn t1_protected_restart_after_durable_local_success_receipt() {
    run_t1_child(LocalWorkerMode::RestartAfterDurableSuccess);
}

#[test]
fn t1_protected_restart_after_durable_local_failure_receipt() {
    run_t1_child(LocalWorkerMode::RestartAfterDurableFailure);
}

#[test]
fn t1_protected_restart_after_durable_local_cancel_receipt() {
    run_t1_child(LocalWorkerMode::RestartAfterDurableCancel);
}

#[derive(Clone, Copy)]
enum LocalWorkerMode {
    Provider,
    Standard,
    Crash,
    CancelBeforeRelease,
    CancelAfterExit,
    CompleteAfterExit,
    RestartAfterMissingArea,
    RestartAfterDurableSuccess,
    RestartAfterDurableFailure,
    RestartAfterDurableCancel,
}

fn run_t1_child(mode: LocalWorkerMode) {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            "t1_positive::t1_protected_provider_http_and_runtime_client_replay_child",
            "--ignored",
            "--nocapture",
        ])
        .env("RUNNE_TEST_T1_TRUST_COMPOSITION", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !matches!(mode, LocalWorkerMode::Provider) {
        command.env("RUNNE_TEST_T1_LOCAL_ONLY", "1");
    } else {
        command.env_remove("RUNNE_TEST_T1_LOCAL_ONLY");
    }
    if matches!(mode, LocalWorkerMode::Crash) {
        command.env("RUNNE_TEST_T1_LOCAL_CRASH_ONLY", "1");
    } else {
        command.env_remove("RUNNE_TEST_T1_LOCAL_CRASH_ONLY");
    }
    if matches!(mode, LocalWorkerMode::RestartAfterMissingArea) {
        command.env("RUNNE_TEST_T1_LOCAL_MISSING_AREA", "1");
    } else {
        command.env_remove("RUNNE_TEST_T1_LOCAL_MISSING_AREA");
    }
    let barrier_mode = match mode {
        LocalWorkerMode::CancelBeforeRelease => Some("pre-release"),
        LocalWorkerMode::CancelAfterExit | LocalWorkerMode::CompleteAfterExit => Some("after-exit"),
        LocalWorkerMode::RestartAfterDurableSuccess
        | LocalWorkerMode::RestartAfterDurableFailure
        | LocalWorkerMode::RestartAfterDurableCancel => Some("after-terminal"),
        _ => None,
    };
    let barrier_directory = barrier_mode.map(|_| tempfile::tempdir().expect("barrier fixture"));
    if let (Some(stage), Some(directory)) = (barrier_mode, barrier_directory.as_ref()) {
        command
            .env("RUNNE_TEST_LOCAL_WORKER_BARRIER", stage)
            .env("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR", directory.path());
    }
    let race = match mode {
        LocalWorkerMode::CancelAfterExit => Some("cancel-before-terminal"),
        LocalWorkerMode::CompleteAfterExit => Some("complete-before-cancel"),
        _ => None,
    };
    if let Some(race) = race {
        command.env("RUNNE_TEST_T1_LOCAL_BARRIER_RACE", race);
    } else {
        command.env_remove("RUNNE_TEST_T1_LOCAL_BARRIER_RACE");
    }
    let terminal_variant = match mode {
        LocalWorkerMode::RestartAfterDurableSuccess => Some("success"),
        LocalWorkerMode::RestartAfterDurableFailure => Some("failure"),
        LocalWorkerMode::RestartAfterDurableCancel => Some("cancel"),
        _ => None,
    };
    if let Some(variant) = terminal_variant {
        command.env("RUNNE_TEST_T1_LOCAL_TERMINAL_VARIANT", variant);
    } else {
        command.env_remove("RUNNE_TEST_T1_LOCAL_TERMINAL_VARIANT");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command.spawn().expect("run isolated T1 child test");
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll isolated T1 child") {
            break status;
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            #[cfg(not(unix))]
            child.kill().expect("kill timed-out T1 child");
            let _ = child.wait();
            panic!("isolated T1 child exceeded 90 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().expect("collect T1 child output");
    let scanner = super::t1_support::frozen_scanner();
    super::assert_absent("T1 child stdout", &output.stdout, &scanner);
    super::assert_absent("T1 child stderr", &output.stderr, &scanner);
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        if line.starts_with("RUN: ") || line.starts_with("PASS: ") || line.starts_with("INFO: ") {
            println!("{line}");
        }
    }
    assert!(
        status.success(),
        "isolated T1 child failed after frozen scans: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
