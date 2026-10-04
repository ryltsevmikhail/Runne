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
    if std::env::var_os("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        command.env("RUNNE_TEST_T1_TRUST_COMPOSITION", "1");
        command.env("RUNNE_TEST_PROTECTED_RUNTIME_ROOT", runtime_root);
        if let Some(barrier) = std::env::var_os("RUNNE_TEST_T1_TRUST_BARRIER_DIR") {
            command.env("RUNNE_TEST_T1_TRUST_BARRIER_DIR", barrier);
        }
        if let Some(mode) = std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER") {
            let mode = mode
                .to_str()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            if !matches!(mode, "pre-release" | "after-exit" | "after-terminal") {
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
        }
        if std::env::var_os("RUNNE_TEST_T1_TRUST_TRANSPORT_LOSS").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            command.env("RUNNE_TEST_T1_TRUST_TRANSPORT_LOSS", "1");
        }
        // D1.6 kill-matrix handshake: the boundary name and its three file
        // paths pass through only under the same T1 fixture selector gate.
        if let Some(boundary) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY") {
            command.env("RUNNE_TEST_KILL_BOUNDARY", boundary);
        }
        if let Some(arm) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_ARM") {
            command.env("RUNNE_TEST_KILL_BOUNDARY_ARM", arm);
        }
        if let Some(marker) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_MARKER") {
            command.env("RUNNE_TEST_KILL_BOUNDARY_MARKER", marker);
        }
        if let Some(release) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_RELEASE") {
            command.env("RUNNE_TEST_KILL_BOUNDARY_RELEASE", release);
        }
    }
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
