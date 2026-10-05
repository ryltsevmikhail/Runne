use super::*;
#[path = "t1_positive_parent/d2_cases.rs"]
mod d2_cases;
#[path = "t1_positive/d2_modes.rs"]
mod d2_modes;
#[path = "t1_positive_parent/d2_restart_tests.rs"]
mod d2_restart_tests;
use d2_modes::LocalWorkerMode;
#[test]
fn t1_protected_provider_http_and_runtime_client_replay() {
    run_t1_child(LocalWorkerMode::Provider);
}

#[test]
fn t1_protected_d2_tool_proposal_persists_pending_without_native_effect() {
    run_t1_child(LocalWorkerMode::D2Pending);
}

#[test]
fn t1_protected_d2_read_create_completes_through_two_approvals() {
    run_t1_child(LocalWorkerMode::D2ReadCreateStop);
}

#[test]
fn t1_protected_d2_finish_before_cancel_preserves_success_receipt() {
    run_t1_child(LocalWorkerMode::D2FinishBeforeCancel);
}

#[test]
fn t1_protected_d2_result_commit_survives_daemon_restart_without_repeating_read() {
    run_t1_child(LocalWorkerMode::D2CrashAfterResult);
}

#[test]
fn t1_protected_d2_crash_before_go_never_repeats_read() {
    run_t1_child(LocalWorkerMode::D2CrashBeforeGo);
}

#[test]
fn t1_protected_d2_crash_after_create_keeps_effect_without_repeating() {
    run_t1_child(LocalWorkerMode::D2CrashAfterCreateEffect);
}

#[test]
fn t1_protected_d2_stale_target_after_read_is_audit_only() {
    run_t1_child(LocalWorkerMode::D2StaleAfterRead);
}

#[test]
fn t1_protected_d2_changed_target_after_result_stops_continuation() {
    run_t1_child(LocalWorkerMode::D2StaleAfterResult);
}

#[test]
fn t1_protected_d2_changed_target_after_both_results_blocks_final_stop() {
    run_t1_child(LocalWorkerMode::D2StaleFinalTarget);
}

#[test]
fn t1_protected_d2_outside_target_is_denied_before_effect() {
    run_t1_child(LocalWorkerMode::D2OutsideTarget);
}

#[test]
fn t1_protected_d2_t1_excluded_target_is_denied_before_effect() {
    run_t1_child(LocalWorkerMode::D2ExcludedTarget);
}

#[test]
fn t1_protected_d2_denial_after_read_prevents_create_effect() {
    run_t1_child(LocalWorkerMode::D2DenyCreate);
}

#[test]
fn t1_protected_d2_denial_prevents_read_effect() {
    run_t1_child(LocalWorkerMode::D2DenyRead);
}

#[test]
fn t1_protected_d2_stale_approval_is_rejected() {
    run_t1_child(LocalWorkerMode::D2StaleApproval);
}

#[test]
fn t1_protected_d2_expired_approval_is_rejected_without_effect() {
    run_t1_child(LocalWorkerMode::D2ExpiredApproval);
}

#[test]
fn t1_protected_d2_trust_revocation_after_approval_blocks_go() {
    run_t1_child(LocalWorkerMode::D2TrustRevokeBeforeLease);
}

#[test]
fn t1_protected_d2_incomplete_provider_tool_stream_never_approves_or_executes() {
    run_t1_child(LocalWorkerMode::D2IncompleteProviderResponse);
}

#[test]
fn t1_protected_d2_unknown_tool_stops_before_approval() {
    run_t1_child(LocalWorkerMode::D2UnknownTool);
}

#[test]
fn t1_protected_d2_malformed_arguments_stop_before_approval() {
    run_t1_child(LocalWorkerMode::D2MalformedArguments);
}

#[test]
fn t1_protected_d2_early_final_stop_is_not_success() {
    run_t1_child(LocalWorkerMode::D2EarlyFinalStop);
}

#[test]
fn t1_protected_d2_changed_target_before_go_has_no_effect() {
    run_t1_child(LocalWorkerMode::D2TargetChangedBeforeGo);
}

#[test]
fn t1_protected_d2_cancel_before_go_has_no_effect() {
    run_t1_child(LocalWorkerMode::D2CancelBeforeGo);
}

#[test]
fn t1_protected_d2_truncated_read_is_audit_only() {
    run_t1_child(LocalWorkerMode::D2TruncatedReadResult);
}

#[test]
fn t1_protected_d2_cancel_after_create_exit_prevents_result_continuation() {
    run_t1_child(LocalWorkerMode::D2CancelAfterCreateEffect);
}

#[test]
fn t1_protected_d2_restart_after_durable_cancel_proves_no_repeat_effect() {
    run_t1_child(LocalWorkerMode::D2CancelRestartAfterCreateEffect);
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
    let (d2_config_home, _provider_barrier) = d2_cases::configure(&mut command, mode);
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
