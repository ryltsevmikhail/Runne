use super::*;
#[path = "t1_positive_parent/d2_cases.rs"]
mod d2_cases;
#[path = "t1_positive/d2_modes.rs"]
mod d2_modes;
#[path = "t1_positive_parent/d2_restart_tests.rs"]
mod d2_restart_tests;
#[path = "t1_positive_parent/local_permission_modes.rs"]
mod local_permission_modes;
#[path = "t1_positive_parent/runner.rs"]
mod runner;
use d2_modes::LocalWorkerMode;
use runner::{run_t1_child, run_t1_child_with_permission};
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
fn t1_protected_d2_permission_mode_effect_matrix() {
    run_t1_child(LocalWorkerMode::D2AskAlways);
    run_t1_child(LocalWorkerMode::D2RiskBased);
    run_t1_child(LocalWorkerMode::D2FullAccess);
}

#[test]
fn t1_protected_d2_managed_ask_requires_create_approval_in_all_modes() {
    run_t1_child(LocalWorkerMode::D2ManagedAskAlways);
    run_t1_child(LocalWorkerMode::D2ManagedAskRiskBased);
    run_t1_child(LocalWorkerMode::D2ManagedAskFullAccess);
}

#[test]
fn t1_protected_d2_approved_target_create_race_after_go_all_modes() {
    for (mode, permission_mode) in [
        (LocalWorkerMode::D2ApprovedTargetRaceAskAlways, "ask_always"),
        (LocalWorkerMode::D2ApprovedTargetRaceRiskBased, "risk_based"),
        (
            LocalWorkerMode::D2ApprovedTargetRaceFullAccess,
            "full_access",
        ),
    ] {
        run_t1_child_with_permission(mode, Some(permission_mode));
    }
}

#[test]
fn t1_protected_d2_permission_mode_downgrade_fences_typed_create() {
    for mode in [
        LocalWorkerMode::D2DowngradeBeforeRelease,
        LocalWorkerMode::D2DowngradeAfterExit,
        LocalWorkerMode::D2DowngradeAfterResult,
        LocalWorkerMode::D2DowngradeAfterStepOutcome,
    ] {
        run_t1_child(mode);
    }
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
    for permission_mode in ["ask_always", "risk_based", "full_access"] {
        run_t1_child_with_permission(LocalWorkerMode::Crash, Some(permission_mode));
    }
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

#[test]
fn t1_protected_local_command_lost_ack_replays_exactly_without_redispatch() {
    run_t1_child(LocalWorkerMode::LocalResultLostAck);
}
