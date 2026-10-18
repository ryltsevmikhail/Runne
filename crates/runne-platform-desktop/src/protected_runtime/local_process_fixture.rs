fn select_launch_artifact(
    state: &ActivationStateStore,
    source: &Path,
    trusted: &ExecutableIdentityV1,
    provider_bound: bool,
) -> Result<(PathBuf, ExecutableIdentityV1), ProtectedBundledRuntimeError> {
    #[cfg(feature = "test-support")]
    if runne_api::test_support::local_native_enrollment_enabled() {
        let expected = source
            .parent()
            .filter(|path| path.file_name().is_some_and(|name| name == "MacOS"))
            .and_then(Path::parent)
            .filter(|path| path.file_name().is_some_and(|name| name == "Contents"))
            .and_then(Path::parent)
            .filter(|path| path.file_name().is_some_and(|name| name == "Runne.app"));
        if !provider_bound
            || source.file_name().is_none_or(|name| name != "runned")
            || expected.is_none()
        {
            return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
        }
        let measured = ExecutableIdentityV1::measure(source)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        if &measured != trusted {
            return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
        }
        return Ok((source.to_path_buf(), measured));
    }
    let selected = state.stage_trusted_executable(source, trusted)?;
    if provider_bound {
        state.stage_provider_writer(source)?;
    }
    Ok(selected)
}

#[cfg(feature = "test-support")]
fn preserve_local_process_environment(
    command: &mut Command,
    runtime_root: &Path,
) -> Result<(), ProtectedBundledRuntimeError> {
    #[cfg(target_os = "linux")]
    preserve_linux_fixture_environment(command, runtime_root)?;
    if runne_api::test_support::local_native_enrollment_enabled() {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
        let keychain = std::env::var_os("RUNNE_CI_MACOS_KEYCHAIN")
            .map(PathBuf::from)
            .ok_or(ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
        if !home.is_absolute()
            || keychain != home.join("Library/Keychains/runne-ci.keychain-db")
            || !keychain.is_file()
        {
            return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
        }
        command.env("HOME", home);
        command.env("RUNNE_CI_MACOS_KEYCHAIN", keychain);
        command.env("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST", "1");
        let scenario = runne_api::test_support::validated_local_native_enrollment_case_name()
            .ok_or(ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
        let root = std::env::var_os("RUNNE_SLICE_E_FIXTURE_ROOT")
            .ok_or(ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
        command.env("RUNNE_SLICE_E_FIXTURE_ROOT", root);
        command.env("RUNNE_SLICE_E_SCENARIO", scenario);
    }
    Ok(())
}

#[cfg(all(feature = "test-support", target_os = "linux"))]
fn preserve_linux_fixture_environment(
    command: &mut Command,
    runtime_root: &Path,
) -> Result<(), ProtectedBundledRuntimeError> {
    if std::env::var_os("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return Ok(());
    }
    command
        .env("RUNNE_TEST_T1_TRUST_COMPOSITION", "1")
        .env("RUNNE_TEST_PROTECTED_RUNTIME_ROOT", runtime_root);
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_LEGACY_SELECTION").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        command.env("RUNNE_TEST_T1_LOCAL_LEGACY_SELECTION", "1");
    }
    preserve_d2_fixture_environment(command)?;
    if let Some(barrier) = std::env::var_os("RUNNE_TEST_T1_TRUST_BARRIER_DIR") {
        command.env("RUNNE_TEST_T1_TRUST_BARRIER_DIR", barrier);
    }
    preserve_worker_barrier_environment(command)?;
    if std::env::var_os("RUNNE_TEST_T1_TRUST_TRANSPORT_LOSS").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        command.env("RUNNE_TEST_T1_TRUST_TRANSPORT_LOSS", "1");
    }
    preserve_kill_boundary_environment(command);
    Ok(())
}

#[cfg(all(feature = "test-support", target_os = "linux"))]
fn preserve_d2_fixture_environment(
    command: &mut Command,
) -> Result<(), ProtectedBundledRuntimeError> {
    if std::env::var_os("RUNNE_TEST_D2_TOOL_PROPOSAL").as_deref() != Some(std::ffi::OsStr::new("1"))
    {
        return Ok(());
    }
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    let metadata = std::fs::metadata(&config_home)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
        }
    }
    command
        .env("XDG_CONFIG_HOME", config_home)
        .env("RUNNE_TEST_D2_TOOL_PROPOSAL", "1");
    preserve_d2_scenario(command)
}

#[cfg(all(feature = "test-support", target_os = "linux"))]
fn preserve_d2_scenario(command: &mut Command) -> Result<(), ProtectedBundledRuntimeError> {
    let Some(scenario) = std::env::var_os("RUNNE_TEST_D2_TOOL_SCENARIO") else {
        return Ok(());
    };
    let scenario = scenario
        .to_str()
        .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    if !matches!(
        scenario,
        "read-create-stop"
            | "finish-before-cancel"
            | "result-commit-crash"
            | "crash-before-go"
            | "crash-pending-approval"
            | "crash-approved-before-lease"
            | "crash-claimed-before-area"
            | "crash-after-create-effect"
            | "stale-after-read"
            | "outside-target"
            | "excluded-target"
            | "cancel-final-response"
            | "stale-final-target"
            | "budget-exhausted"
            | "deny-create"
            | "deny-read"
            | "stale-approval"
            | "approval-expiry"
            | "revoke-before-lease"
            | "incomplete-provider-response"
            | "unknown-tool-proposal"
            | "malformed-tool-arguments"
            | "early-final-stop"
            | "approved-target-create-race"
            | "target-changed-before-go"
            | "cancel-before-go"
            | "cancel-after-create-effect"
            | "cancel-restart-after-create-effect"
            | "stale-after-result"
            | "truncated-read-result"
            | "restart-started-before-cycle"
            | "restart-cycle-before-budget"
            | "restart-context-committed"
            | "restart-cancelled-before-budget"
            | "restart-plan-committed"
            | "restart-proposal-before-invocation"
            | "restart-dispatched-remote-unknown"
    ) {
        return Err(ProtectedBundledRuntimeError::InvalidState);
    }
    command.env("RUNNE_TEST_D2_TOOL_SCENARIO", scenario);
    if scenario == "approved-target-create-race"
        && std::env::var("RUNNE_TEST_T1_APPROVED_TARGET_RACE").as_deref() == Ok("1")
    {
        command.env("RUNNE_TEST_T1_APPROVED_TARGET_RACE", "1");
    }
    if let Some(stage) = std::env::var_os("RUNNE_TEST_D2_KILL_AT_STAGE") {
        let stage = stage
            .to_str()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        if !matches!(
            stage,
            "start_cycle"
                | "cycle_started"
                | "context_committed"
                | "plan_committed"
                | "proposal_received"
                | "provider_uncertain"
        ) {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        command.env("RUNNE_TEST_D2_KILL_AT_STAGE", stage);
    }
    if matches!(scenario, "cancel-final-response" | "stale-final-target") {
        let barrier = std::env::var_os("RUNNE_TEST_D2_PROVIDER_BARRIER_DIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_dir())
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        command.env("RUNNE_TEST_D2_PROVIDER_BARRIER_DIR", barrier);
    }
    Ok(())
}

#[cfg(all(feature = "test-support", target_os = "linux"))]
fn preserve_worker_barrier_environment(
    command: &mut Command,
) -> Result<(), ProtectedBundledRuntimeError> {
    let Some(mode) = std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER") else {
        return Ok(());
    };
    let mode = mode
        .to_str()
        .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    if !matches!(
        mode,
        "pre-release"
            | "after-exit"
            | "after-terminal"
            | "after-result-before-step-outcome"
            | "approved-before-lease"
            | "claimed-before-area"
    ) {
        return Err(ProtectedBundledRuntimeError::InvalidState);
    }
    let directory = std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR")
        .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    command
        .env("RUNNE_TEST_LOCAL_WORKER_BARRIER", mode)
        .env("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR", directory);
    if let Some(race) = std::env::var_os("RUNNE_TEST_T1_LOCAL_BARRIER_RACE") {
        let race = race
            .to_str()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        if !matches!(race, "cancel-before-terminal" | "complete-before-cancel") {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        command.env("RUNNE_TEST_T1_LOCAL_BARRIER_RACE", race);
    }
    Ok(())
}

#[cfg(all(feature = "test-support", target_os = "linux"))]
fn preserve_kill_boundary_environment(command: &mut Command) {
    for name in [
        "RUNNE_TEST_KILL_BOUNDARY",
        "RUNNE_TEST_KILL_BOUNDARY_ARM",
        "RUNNE_TEST_KILL_BOUNDARY_MARKER",
        "RUNNE_TEST_KILL_BOUNDARY_RELEASE",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

#[cfg(feature = "test-support")]
impl ProtectedBundledRuntimeSupervisor {
    /// Kills and waits only for the exact retained disposable-fixture daemon.
    #[doc(hidden)]
    pub fn crash_local_fixture_process(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        runne_api::test_support::validated_local_native_enrollment_case_name()
            .ok_or(ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        process
            .child
            .kill()
            .and_then(|()| process.child.wait().map(|_| ()))
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
    }
}
