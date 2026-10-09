use super::*;

pub(super) fn configure(
    command: &mut std::process::Command,
    mode: LocalWorkerMode,
) -> (Option<tempfile::TempDir>, Option<tempfile::TempDir>) {
    if matches!(
        mode,
        LocalWorkerMode::D2AskAlways | LocalWorkerMode::D2RiskBased | LocalWorkerMode::D2FullAccess
    ) {
        command.env("RUNNE_TEST_T1_CREDENTIAL_COMPANION", "1");
    } else {
        command.env_remove("RUNNE_TEST_T1_CREDENTIAL_COMPANION");
    }
    command.env_remove("RUNNE_TEST_T1_APPROVED_TARGET_RACE");
    if mode.d2_scenario() == Some("approved-target-create-race") {
        command.env("RUNNE_TEST_T1_APPROVED_TARGET_RACE", "1");
    }
    if mode.d2_managed_ask() {
        command.env("RUNNE_TEST_D2_MANAGED_ASK", "1");
    } else {
        command.env_remove("RUNNE_TEST_D2_MANAGED_ASK");
    }
    if let Some(mode) = mode.d2_permission_mode() {
        command.env("RUNNE_TEST_D2_PERMISSION_MODE", mode);
    } else {
        command.env_remove("RUNNE_TEST_D2_PERMISSION_MODE");
    }
    if matches!(mode, LocalWorkerMode::LocalPermissionFullAccessDowngrade) {
        command.env("RUNNE_TEST_T1_LOCAL_FULL_ACCESS_LIVE_DOWNGRADE", "1");
    } else {
        command.env_remove("RUNNE_TEST_T1_LOCAL_FULL_ACCESS_LIVE_DOWNGRADE");
    }
    if matches!(
        mode,
        LocalWorkerMode::LocalPermissionFullAccessUnavailableNetwork
    ) {
        command.env("RUNNE_TEST_T1_LOCAL_UNAVAILABLE_NETWORK", "1");
    } else {
        command.env_remove("RUNNE_TEST_T1_LOCAL_UNAVAILABLE_NETWORK");
    }
    if matches!(mode, LocalWorkerMode::LocalPermissionLegacySelection) {
        command.env("RUNNE_TEST_T1_LOCAL_LEGACY_SELECTION", "1");
    } else {
        command.env_remove("RUNNE_TEST_T1_LOCAL_LEGACY_SELECTION");
    }
    let config = if mode.is_d2() {
        Some(write_d2_config(command, mode))
    } else {
        command.env_remove("RUNNE_TEST_D2_TOOL_PROPOSAL");
        command.env_remove("RUNNE_TEST_D2_TOOL_SCENARIO");
        None
    };
    let barrier = matches!(
        mode,
        LocalWorkerMode::D2CancelFinalResponse
            | LocalWorkerMode::D2StaleFinalTarget
            | LocalWorkerMode::D2CrashApprovedBeforeLease
            | LocalWorkerMode::D2CrashClaimedBeforeArea
    )
    .then(|| tempfile::tempdir().expect("D2 provider barrier fixture"));
    if let Some(directory) = barrier.as_ref() {
        secure_provider_barrier_permissions(directory.path());
        command.env("RUNNE_TEST_D2_PROVIDER_BARRIER_DIR", directory.path());
    }
    (config, barrier)
}

#[cfg(unix)]
fn secure_provider_barrier_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("restrict provider barrier diagnostic directory");
}

#[cfg(not(unix))]
fn secure_provider_barrier_permissions(_: &std::path::Path) {}

pub(super) const fn child_timeout_seconds(mode: LocalWorkerMode) -> u64 {
    if matches!(
        mode,
        LocalWorkerMode::D2ExpiredApproval | LocalWorkerMode::LocalPermissionAskAlways
    ) {
        200
    } else {
        90
    }
}

fn write_d2_config(
    command: &mut std::process::Command,
    mode: LocalWorkerMode,
) -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("D2 owner-private config home");
    let daemon_config = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon_config).expect("create D2 config directory");
    secure_config_permissions(directory.path(), &daemon_config);
    let contents = "schema_version=2\n[d2_safe_tool_loop_budget]\ntoken_budget_limit=1000000\ncost_budget_limit_micros=5000000\n".to_owned();
    let path = daemon_config.join("config.toml");
    std::fs::write(&path, contents).expect("write finite fixture-only D2 budget");
    secure_file_permissions(&path);
    command
        .env("XDG_CONFIG_HOME", directory.path())
        .env("RUNNE_TEST_D2_TOOL_PROPOSAL", "1");
    if let Some(scenario) = mode.d2_scenario() {
        command.env("RUNNE_TEST_D2_TOOL_SCENARIO", scenario);
    }
    directory
}

#[cfg(unix)]
fn secure_config_permissions(home: &std::path::Path, config: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700))
        .expect("restrict D2 config home");
    std::fs::set_permissions(config, std::fs::Permissions::from_mode(0o700))
        .expect("restrict D2 config directory");
}

#[cfg(not(unix))]
fn secure_config_permissions(_: &std::path::Path, _: &std::path::Path) {}

#[cfg(unix)]
fn secure_file_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict fixture D2 config permissions");
}

#[cfg(not(unix))]
fn secure_file_permissions(_: &std::path::Path) {}

#[test]
fn t1_protected_d2_cancel_during_final_provider_response_never_succeeds() {
    run_t1_child(LocalWorkerMode::D2CancelFinalResponse);
}

#[test]
fn t1_protected_d2_effect_budget_blocks_third_native_operation() {
    run_t1_child(LocalWorkerMode::D2BudgetExhausted);
}
