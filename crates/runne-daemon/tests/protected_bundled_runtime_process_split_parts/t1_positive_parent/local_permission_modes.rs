use super::{d2_modes::LocalWorkerMode, run_t1_child};

#[test]
fn t1_protected_local_command_permission_mode_x2_effect_matrix() {
    for mode in [
        LocalWorkerMode::LocalPermissionAskAlways,
        LocalWorkerMode::LocalPermissionRiskBased,
        LocalWorkerMode::LocalPermissionFullAccess,
    ] {
        run_t1_child(mode);
    }
}

#[test]
fn t1_protected_local_command_full_access_live_downgrade() {
    run_t1_child(LocalWorkerMode::LocalPermissionFullAccessDowngrade);
}

#[test]
fn t1_protected_local_command_unavailable_network_reopen() {
    run_t1_child(LocalWorkerMode::LocalPermissionFullAccessUnavailableNetwork);
}

#[test]
fn t1_protected_local_command_legacy_current_route_rejects_before_effect() {
    run_t1_child(LocalWorkerMode::LocalPermissionLegacySelection);
}

#[test]
fn t1_protected_local_command_precapture_failure_settles() {
    for mode in [
        LocalWorkerMode::LocalPermissionPreCaptureExecutable,
        LocalWorkerMode::LocalPermissionPreCaptureCwd,
    ] {
        run_t1_child(mode);
    }
}
