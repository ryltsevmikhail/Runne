use super::{d2_modes::LocalWorkerMode, run_t1_child};

#[test]
fn t1_protected_d2_restart_stops_before_pending_approval_without_effect() {
    run_t1_child(LocalWorkerMode::D2CrashPendingApproval);
}

#[test]
fn t1_protected_d2_restart_stops_after_approval_before_lease_without_effect() {
    run_t1_child(LocalWorkerMode::D2CrashApprovedBeforeLease);
}

#[test]
fn t1_protected_d2_restart_stops_after_claim_before_area_without_effect() {
    run_t1_child(LocalWorkerMode::D2CrashClaimedBeforeArea);
}

#[test]
fn t1_protected_d2_restart_stops_started_before_cycle_with_zero_effect() {
    run_t1_child(LocalWorkerMode::D2RestartStartedBeforeCycle);
}

#[test]
fn t1_protected_d2_restart_stops_cycle_before_budget_with_zero_effect() {
    run_t1_child(LocalWorkerMode::D2RestartCycleBeforeBudget);
}

#[test]
fn t1_protected_d2_restart_stops_after_context_before_plan_with_zero_effect() {
    run_t1_child(LocalWorkerMode::D2RestartContextCommitted);
}

#[test]
fn t1_protected_d2_restart_preserves_cancel_before_budget_without_effect() {
    run_t1_child(LocalWorkerMode::D2RestartCancelledBeforeBudget);
}

#[test]
fn t1_protected_d2_restart_stops_plan_committed_before_admission_with_zero_effect() {
    run_t1_child(LocalWorkerMode::D2RestartPlanCommitted);
}

#[test]
fn t1_protected_d2_restart_stops_after_durable_proposal_before_invocation() {
    run_t1_child(LocalWorkerMode::D2RestartProposalBeforeInvocation);
}

#[test]
fn t1_protected_d2_restart_preserves_dispatched_remote_unknown_without_retry() {
    run_t1_child(LocalWorkerMode::D2RestartRemoteUnknown);
}
