// Windows protected bundled-runtime launcher.

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
impl DevelopmentBundledRuntimeLauncher {
    fn launch_windows(
        &self,
        spec: &ProtectedBundledRuntimeLaunchSpec,
        controls: &mut LaunchTestControls,
    ) -> Result<ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeError> {
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
        let profile = expected_profile()?;
        let state_store = ActivationStateStore::open(&runtime_root)?;
        let (launch_executable_path, executable) = state_store
            .stage_trusted_executable(&executable_path, spec.trusted_source_identity())?;
        let stable = state_store.load_stable()?;
        let pending = state_store.load_pending()?;
        let disposition = match (pending, stable) {
            (Some(pending), stable) => {
                if pending.executable() != &executable
                    || pending.profile() != &profile
                    || stable.as_ref().is_some_and(|stable| stable != pending.stable())
                {
                    return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
                }
                ActivationDispositionV1::ResumeFirstActivation(Box::new(pending))
            }
            (None, Some(stable)) => {
                if stable.principal_id() != LOCAL_PRINCIPAL
                    || stable.profile_id() != profile.profile_id()
                    || stable.profile_hash() != profile.profile_hash()
                    || stable.capability_digest() != profile.capability_digest()
                {
                    return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
                }
                ActivationDispositionV1::Existing(Box::new(stable))
            }
            (None, None) => ActivationDispositionV1::FirstActivation,
        };
        let issued_at = unix_millis()?;
        let expires_at = issued_at
            .checked_add(
                u64::try_from(LAUNCH_TIMEOUT.as_millis())
                    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?,
            )
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
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
            *uuid::Uuid::now_v7().as_bytes(),
            self.desktop_host_instance_id,
            secret,
            issued_at,
            expires_at,
            LOCAL_PRINCIPAL,
            profile,
            executable,
            runtime_root,
            disposition,
        )?;
        let mut request = match spec.provider_activation() {
            Some(binding) => DesktopLaunchRequest::V2(ProtectedLaunchRequestV2::new(
                request_v1,
                binding.clone(),
            )?),
            None => DesktopLaunchRequest::V1(request_v1),
        };
        let mut windows_channel = create_windows_channel()?;
        let mut command = Command::new(&launch_executable_path);
        command.env_clear().stdin(windows_channel.child_stdin());
        if controls.capture_output {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
        let child = command.spawn().map_err(|_| ProtectedBundledRuntimeError::SpawnFailed)?;
        let job = match assign_kill_on_close_job(&child) {
            Ok(job) => job,
            Err(error) => {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        drop(command);
        let mut child = Some(child);
        let mut parent_channel = windows_channel
            .connect_parent()
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        #[cfg(feature = "test-support")]
        let captured_stdout = child.as_mut().and_then(|child| child.stdout.take());
        #[cfg(feature = "test-support")]
        let captured_stderr = child.as_mut().and_then(|child| child.stderr.take());
        let result = (|| {
            let spawned_identity = ExecutableIdentityV1::measure(&launch_executable_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            if spawned_identity != *request.executable() {
                return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
            }
            write_frame(&mut parent_channel, &Zeroizing::new(request.encode_frame()?))?;
            let mut keys = request.derive_keys_and_forget();
            let prepared_pending = if matches!(
                request.activation_disposition(),
                ActivationDispositionV1::FirstActivation
            ) {
                let prepared = ProtectedFirstActivationPreparedV1::decode_frame(&read_frame(
                    &mut parent_channel,
                )?)
                .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)?;
                let request_v1 = request
                    .compatibility()
                    .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
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
                commit.sign(&keys);
                write_frame(
                    &mut parent_channel,
                    &Zeroizing::new(commit.encode_frame().map_err(|_| {
                        LaunchAuthorityError::InvalidContract
                    })?),
                )?;
                controls.checkpoint(ActivationCheckpoint::AfterCommit)?;
                Some(pending)
            } else {
                None
            };
            let ready = request.decode_ready(&read_frame(&mut parent_channel)?, &keys)?;
            if let Some(readiness) = ready.provider_readiness()
                && provider_readiness_blocks_launch(readiness)
            {
                return Err(ProtectedBundledRuntimeError::ProviderActivationNotReady(readiness));
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
            let runtime_profile = request.runtime_profile(&ready, unix_millis()?, &keys)?;
            keys.forget_bootstrap_key();
            controls.checkpoint(ActivationCheckpoint::BeforeFinalPin)?;
            state_store.persist_stable_exact(ready.stable(), controls)?;
            controls.checkpoint(ActivationCheckpoint::AfterFinalPin)?;
            state_store.remove_pending()?;
            let activation = ready.into_process_activation(request)?;
            Ok(ProtectedBundledRuntimeProcess {
                child: child.take().ok_or(ProtectedBundledRuntimeError::InvalidState)?,
                job,
                channel: parent_channel,
                keys,
                activation,
                runtime_profile: Some(runtime_profile),
                renewal_sequence: 0,
                #[cfg(all(any(unix, windows), feature = "protected-channel-integration"))]
                root_control_sequence: 0,
                graceful_requested: false,
                #[cfg(feature = "test-support")]
                captured_stdout,
                #[cfg(feature = "test-support")]
                captured_stderr,
            })
        })();
        if result.is_err() && let Some(child) = child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
}
