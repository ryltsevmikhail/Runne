use super::*;

pub(super) fn run_t1_child(mode: LocalWorkerMode) {
    run_t1_child_with_permission(mode, None);
}

pub(super) fn run_t1_child_with_permission(mode: LocalWorkerMode, permission_mode: Option<&str>) {
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
    let (d2_config_home, _provider_barrier) = d2_cases::configure(&mut command, mode);
    if let Some(permission_mode) = permission_mode {
        command.env("RUNNE_TEST_D2_PERMISSION_MODE", permission_mode);
    }
    if let Some(stage) = mode.d2_kill_stage() {
        command.env("RUNNE_TEST_D2_KILL_AT_STAGE", stage);
    } else {
        command.env_remove("RUNNE_TEST_D2_KILL_AT_STAGE");
    }
    if matches!(mode, LocalWorkerMode::D2RestartRemoteUnknown) {
        command.env("RUNNE_TEST_T1_TRUST_TRANSPORT_LOSS", "1");
    } else {
        command.env_remove("RUNNE_TEST_T1_TRUST_TRANSPORT_LOSS");
    }
    if !matches!(mode, LocalWorkerMode::Provider) && !mode.is_d2() {
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
    let barrier_mode = mode.barrier_mode();
    let barrier_directory = barrier_mode.map(|_| tempfile::tempdir().expect("barrier fixture"));
    if let (Some(stage), Some(directory)) = (barrier_mode, barrier_directory.as_ref()) {
        command
            .env("RUNNE_TEST_LOCAL_WORKER_BARRIER", stage)
            .env("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR", directory.path());
    }
    if let Some(case) = mode.local_precapture_failure_case() {
        command.env("RUNNE_TEST_T1_LOCAL_PRECAPTURE_FAILURE_CASE", case);
    } else {
        command.env_remove("RUNNE_TEST_T1_LOCAL_PRECAPTURE_FAILURE_CASE");
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
    // The lost-ACK child cannot learn the daemon-generated taskrun id before
    // the daemon is spawned, so the terminal TaskRunCompleted commit is gated
    // by this fixed test-controlled key (RUNNE_TEST_COMMIT_GATE_TERMINAL_KEY)
    // instead. Arming immediately is safe: submit commits are keyed by the
    // client command id, which never equals this literal. The directory must
    // outlive the child, like barrier_directory above.
    let gate_directory = if matches!(mode, LocalWorkerMode::LocalResultLostAck) {
        Some(tempfile::tempdir().expect("lost-ACK terminal commit-gate fixture"))
    } else {
        None
    };
    if let Some(gate_directory) = gate_directory.as_ref() {
        std::fs::write(
            gate_directory.path().join("lost-ack-commit-gate.arm"),
            b"armed",
        )
        .expect("arm lost-ACK terminal commit gate");
        command
            .env("RUNNE_TEST_T1_LOCAL_LOST_ACK", "1")
            .env("RUNNE_TEST_COMMIT_GATE_TERMINAL_KEY", "lost-ack-terminal")
            .env("RUNNE_TEST_COMMIT_GATE_COMMAND_ID", "lost-ack-terminal")
            .env(
                "RUNNE_TEST_COMMIT_GATE_FILE",
                gate_directory.path().join("lost-ack-commit-gate.marker"),
            )
            .env(
                "RUNNE_TEST_COMMIT_GATE_RELEASE",
                gate_directory.path().join("lost-ack-commit-gate.release"),
            )
            .env(
                "RUNNE_TEST_COMMIT_GATE_ARM_FILE",
                gate_directory.path().join("lost-ack-commit-gate.arm"),
            );
    } else {
        command.env_remove("RUNNE_TEST_T1_LOCAL_LOST_ACK");
        command.env_remove("RUNNE_TEST_COMMIT_GATE_TERMINAL_KEY");
        command.env_remove("RUNNE_TEST_COMMIT_GATE_COMMAND_ID");
        command.env_remove("RUNNE_TEST_COMMIT_GATE_FILE");
        command.env_remove("RUNNE_TEST_COMMIT_GATE_RELEASE");
        command.env_remove("RUNNE_TEST_COMMIT_GATE_ARM_FILE");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command.spawn().expect("run isolated T1 child test");
    let timeout_seconds = d2_cases::child_timeout_seconds(mode);
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
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
            panic!("isolated T1 child exceeded {timeout_seconds} seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().expect("collect T1 child output");
    drop(d2_config_home);
    let scanner = super::super::t1_support::frozen_scanner();
    super::super::assert_absent("T1 child stdout", &output.stdout, &scanner);
    super::super::assert_absent("T1 child stderr", &output.stderr, &scanner);
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
