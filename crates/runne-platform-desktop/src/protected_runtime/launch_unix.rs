impl DevelopmentBundledRuntimeLauncher {
    #[cfg(unix)]
    #[allow(clippy::too_many_lines)]
    fn launch_unix(
        &self,
        spec: &ProtectedBundledRuntimeLaunchSpec,
        controls: &mut LaunchTestControls,
    ) -> Result<ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeError> {
        let mut diagnostic = ProtectedLaunchDiagnostic::new();
        let executable_path = validate_executable_path(spec.executable())?;
        if executable_path != spec.executable() {
            return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
        }
        let runtime_root = ensure_owner_private_directory(spec.runtime_root())?;
        if runtime_root != spec.runtime_root() {
            return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
        }
        let current_source = ExecutableIdentityV1::measure(&executable_path)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        if &current_source != spec.trusted_source_identity() {
            return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
        }
        let profile =
            expected_profile_for_launch(&runtime_root, spec.provider_activation().is_some())?;
        let state_store = ActivationStateStore::open(&runtime_root)?;
        let (launch_executable_path, executable) = select_launch_artifact(
            &state_store,
            &executable_path,
            spec.trusted_source_identity(),
            spec.provider_activation().is_some(),
        )?;
        #[cfg(target_os = "linux")]
        let launched_executable = open_launch_image(&launch_executable_path, &executable)?;
        let stable = state_store.load_stable()?;
        let pending = state_store.load_pending()?;

        // Forward profile rebind: identity fields are preserved and authenticated
        // by the daemon; the stored binding is replaced only after signed ready.
        let mut rebind_previous: Option<Box<StableRuntimeBindingV1>> = None;
        let disposition = match (pending, stable) {
            (Some(pending), stable) => {
                if pending.executable() != &executable
                    || pending.profile() != &profile
                    || stable
                        .as_ref()
                        .is_some_and(|stable| stable != pending.stable())
                {
                    return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
                }
                ActivationDispositionV1::ResumeFirstActivation(Box::new(pending))
            }
            (None, Some(stable)) => match stable_rebind_decision(&stable, &profile)? {
                StableProfileMatch::Exact => ActivationDispositionV1::Existing(Box::new(stable)),
                StableProfileMatch::Rebind(rebound) => {
                    rebind_previous = Some(Box::new(stable));
                    ActivationDispositionV1::Existing(Box::new(rebound))
                }
            },
            (None, None) => ActivationDispositionV1::FirstActivation,
        };

        #[cfg(target_os = "linux")]
        let provider_bus_address = linux_provider_bus::address_for_launch(spec)?;

        let issued_at = unix_millis()?;
        let expires_at = issued_at
            .checked_add(
                u64::try_from(LAUNCH_TIMEOUT.as_millis())
                    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?,
            )
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let launch_authority_id = *uuid::Uuid::now_v7().as_bytes();
        let mut secret_bytes = controls
            .secret_override
            .take()
            .map_or([0_u8; 32], |secret| *secret);
        if secret_bytes == [0; 32] && controls.fail_at.is_none() && !controls.capture_output {
            OsRng.fill_bytes(&mut secret_bytes);
        }
        if secret_bytes == [0; 32] {
            return Err(ProtectedBundledRuntimeError::LaunchAuthority(
                LaunchAuthorityError::MissingLaunchAuthority,
            ));
        }
        let secret = LaunchSecret::from_bytes(secret_bytes)?;
        secret_bytes.fill(0);
        let request_v1 = ProtectedLaunchRequestV1::new(
            launch_authority_id,
            self.desktop_host_instance_id,
            secret,
            issued_at,
            expires_at,
            LOCAL_PRINCIPAL,
            profile,
            executable,
            runtime_root.clone(),
            disposition,
        )?;
        let mut request = match spec.provider_activation() {
            Some(binding) => DesktopLaunchRequest::V2(ProtectedLaunchRequestV2::new(
                request_v1,
                binding.clone(),
            )?),
            None => DesktopLaunchRequest::V1(request_v1),
        };

        let (mut parent_channel, child_channel) = UnixStream::pair()
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        parent_channel
            .set_read_timeout(Some(launch_timeout()))
            .and_then(|()| parent_channel.set_write_timeout(Some(launch_timeout())))
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        let child_stdin = Stdio::from(OwnedFd::from(child_channel));
        let mut command = Command::new(&launch_executable_path);
        command.env_clear().stdin(child_stdin);
        if let (Some(writer), Some(reader)) =
            (spec.credential_writer(), spec.credential_reader())
        {
            command
                .env("RUNNE_CLI_PATH", writer)
                .env("RUNNE_DAEMON_PATH", reader);
        }
        for name in [
            "RUNNE_TEST_DEEPSEEK_LOOPBACK_ADDR",
            "RUNNE_TEST_DEEPSEEK_LOOPBACK_CERT",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        terminal_installation::apply(&mut command, &state_store)?;
        #[cfg(target_os = "linux")]
        linux_provider_bus::apply_to_command(
            &mut command,
            spec.provider_activation().is_some(),
            provider_bus_address.as_ref(),
        )?;
        #[cfg(all(
            target_os = "linux",
            feature = "linux-native-enrollment-qualification"
        ))]
        crate::provider_credential_broker::linux_native_enrollment_qualification::forward_fixture_root(&mut command)
            .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)?;
        #[cfg(feature = "test-support")]
        preserve_local_process_environment(&mut command, spec.runtime_root())?;
        // Test-support-only fault-injection hook: forwards the durable
        // commit-gate handshake variables into the owned child so the store
        // can hold the post-commit/pre-ACK boundary for fault tests.
        #[cfg(feature = "test-support")]
        for name in [
            "RUNNE_TEST_COMMIT_GATE_FILE",
            "RUNNE_TEST_COMMIT_GATE_RELEASE",
            "RUNNE_TEST_COMMIT_GATE_COMMAND_ID",
            "RUNNE_TEST_COMMIT_GATE_TERMINAL_KEY",
            "RUNNE_TEST_COMMIT_GATE_ARM_FILE",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        if controls.capture_output {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
        let Ok(child) = command.spawn() else {
            let error = ProtectedBundledRuntimeError::SpawnFailed;
            diagnostic.at("spawn");
            diagnostic.report(error);
            return Err(error);
        };
        // `Command` retains the parent-side configuration. Drop it before
        // waiting for a frame so an early child exit closes the inherited
        // protected channel instead of being misreported as a readiness
        // timeout.
        drop(command);
        let mut child = Some(child);
        #[cfg(feature = "test-support")]
        let captured_stdout = child.as_mut().and_then(|child| child.stdout.take());
        #[cfg(feature = "test-support")]
        let captured_stderr = child.as_mut().and_then(|child| child.stderr.take());

        diagnostic.at("child_identity");
        let result = (|| {
            let spawned_identity = ExecutableIdentityV1::measure(&launch_executable_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            if spawned_identity != *request.executable() {
                return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
            }
            diagnostic.at("launch_request_encode");
            let launch_frame = Zeroizing::new(request.encode_frame()?);
            diagnostic.at("launch_request_write");
            write_frame(&mut parent_channel, &launch_frame)?;
            let mut keys = request.derive_keys_and_forget();

            let prepared_pending = if matches!(
                request.activation_disposition(),
                ActivationDispositionV1::FirstActivation
            ) {
                diagnostic.at("first_activation_prepare_read");
                let prepared_frame = read_frame(&mut parent_channel)?;
                let prepared = ProtectedFirstActivationPreparedV1::decode_frame(&prepared_frame)
                    .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)?;
                let request_v1 = request
                    .compatibility()
                    .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
                diagnostic.at("first_activation_prepare_verify");
                prepared.verify_exact(request_v1, &keys)?;
                controls.checkpoint(ActivationCheckpoint::BeforePreparePersistence)?;
                state_store.persist_pending_exact(prepared.pending(), controls)?;
                controls.checkpoint(ActivationCheckpoint::AfterPreparePersistence)?;
                let pending = prepared.pending().clone();
                controls.checkpoint(ActivationCheckpoint::BeforeCommit)?;
                let mut commit = ProtectedFirstActivationCommitV1::new(
                    request_v1.launch_authority_id(),
                    request_v1.desktop_host_instance_id(),
                    pending.clone(),
                );
                diagnostic.at("first_activation_commit_encode");
                commit.sign(&keys);
                let commit_frame = Zeroizing::new(
                    commit
                        .encode_frame()
                        .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                );
                diagnostic.at("first_activation_commit_write");
                write_frame(&mut parent_channel, &commit_frame)?;
                controls.checkpoint(ActivationCheckpoint::AfterCommit)?;
                Some(pending)
            } else {
                None
            };

            diagnostic.at("ready_read");
            let ready_frame = read_frame(&mut parent_channel)?;
            diagnostic.at("ready_decode_verify");
            let ready = request.decode_ready(&ready_frame, &keys)?;
            diagnostic.at("provider_readiness");
            if let Some(readiness) = ready.provider_readiness()
                && provider_readiness_blocks_launch(readiness)
            {
                return Err(ProtectedBundledRuntimeError::ProviderActivationNotReady(
                    readiness,
                ));
            }
            controls.checkpoint(ActivationCheckpoint::AfterEventLogCreation)?;
            if prepared_pending
                .as_ref()
                .is_some_and(|pending| ready.stable() != pending.stable())
            {
                return Err(ProtectedBundledRuntimeError::LaunchAuthority(
                    LaunchAuthorityError::FirstActivationPreparationMismatch,
                ));
            }
            diagnostic.at("runtime_profile_create");
            let runtime_profile = request.runtime_profile(&ready, unix_millis()?, &keys)?;
            keys.forget_bootstrap_key();
            diagnostic.at("final_pin");
            controls.checkpoint(ActivationCheckpoint::BeforeFinalPin)?;
            match &rebind_previous {
                Some(previous) => {
                    state_store.migrate_stable_exact(previous, ready.stable(), controls)?;
                }
                None => state_store.persist_stable_exact(ready.stable(), controls)?,
            }
            controls.checkpoint(ActivationCheckpoint::AfterFinalPin)?;
            state_store.remove_pending()?;
            diagnostic.at("process_activation");
            let activation = ready.into_process_activation(request)?;
            Ok(ProtectedBundledRuntimeProcess {
                child: child
                    .take()
                    .ok_or(ProtectedBundledRuntimeError::InvalidState)?,
                #[cfg(target_os = "linux")]
                linux_launch_image: Some(LinuxLaunchImage {
                    runtime_root: runtime_root.clone(),
                    executable: launched_executable,
                }),
                channel: parent_channel,
                keys,
                activation,
                runtime_profile: Some(runtime_profile),
                renewal_sequence: 0,
                #[cfg(all(any(unix, windows), feature = "protected-channel-integration"))]
                root_control_sequence: 0,
                graceful_requested: false,
                graceful_acknowledged: false,
                enrollment_broker_facts: None,
                #[cfg(feature = "test-support")]
                captured_stdout,
                #[cfg(feature = "test-support")]
                captured_stderr,
            })
        })();

        if let Err(error) = &result {
            diagnostic.report(*error);
        }
        if result.is_err()
            && let Some(child) = child.as_mut()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
}
