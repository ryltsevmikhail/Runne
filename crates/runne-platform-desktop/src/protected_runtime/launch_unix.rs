impl DevelopmentBundledRuntimeLauncher {
    #[cfg(unix)]
    #[allow(clippy::too_many_lines)]
    fn launch_unix(
        &self,
        spec: &ProtectedBundledRuntimeLaunchSpec,
        controls: &mut LaunchTestControls,
    ) -> Result<ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeError> {
        let executable_path = validate_executable_path(spec.executable())?;
        eprintln!(
            "runne-launch-diag: enter exec={:?} len={}",
            executable_path.display(),
            std::fs::metadata(&executable_path).map_or(0, |metadata| metadata.len())
        );
        if executable_path != spec.executable() {
            return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
        }
        let runtime_root = ensure_owner_private_directory(spec.runtime_root())?;
        if runtime_root != spec.runtime_root() {
            return Err(ProtectedBundledRuntimeError::RuntimeRootUnavailable);
        }
        let current_source = ExecutableIdentityV1::measure(&executable_path)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        let hex_short = |bytes: &[u8; 32]| -> String { hex::encode(&bytes[..8]) };
        eprintln!(
            "runne-launch-diag: current_sha={} trusted_sha={} current_path_sha={} trusted_path_sha={} current_len={} trusted_len={}",
            hex_short(current_source.executable_sha256()),
            hex_short(spec.trusted_source_identity().executable_sha256()),
            hex_short(current_source.canonical_path_sha256()),
            hex_short(spec.trusted_source_identity().canonical_path_sha256()),
            current_source.byte_length(),
            spec.trusted_source_identity().byte_length()
        );
        if &current_source != spec.trusted_source_identity() {
            eprintln!("runne-launch-diag: IDENTITY MISMATCH at source comparison");
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
        eprintln!(
            "runne-launch-diag: staged ok path={:?}",
            launch_executable_path.display().to_string()
        );
        let stable = state_store.load_stable()?;
        let pending = state_store.load_pending()?;

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

        let (mut parent_channel, child_channel) = UnixStream::pair()
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        parent_channel
            .set_read_timeout(Some(launch_timeout()))
            .and_then(|()| parent_channel.set_write_timeout(Some(launch_timeout())))
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        let child_stdin = Stdio::from(OwnedFd::from(child_channel));
        let mut command = Command::new(&launch_executable_path);
        command.env_clear().stdin(child_stdin);
        #[cfg(feature = "test-support")]
        preserve_local_process_environment(&mut command)?;
        if controls.capture_output {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            // TEMP diag: capture child stderr (protected-activation investigation)
            command.stdout(Stdio::null()).stderr(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/tmp/runne-live/runned-child.err")
                    .map_or_else(|_| Stdio::null(), Stdio::from),
            );
        }
        let child = command
            .spawn()
            .map_err(|_| ProtectedBundledRuntimeError::SpawnFailed)?;
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

        let result = (|| {
            let spawned_identity = ExecutableIdentityV1::measure(&launch_executable_path)
                .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
            eprintln!(
                "runne-launch-diag: spawned_sha={} spawned_path_sha={} spawned_len={}",
                hex_short(spawned_identity.executable_sha256()),
                hex_short(spawned_identity.canonical_path_sha256()),
                spawned_identity.byte_length()
            );
            if spawned_identity != *request.executable() {
                return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
            }
            let launch_frame = Zeroizing::new(request.encode_frame()?);
            write_frame(&mut parent_channel, &launch_frame)?;
            let mut keys = request.derive_keys_and_forget();

            let prepared_pending = if matches!(
                request.activation_disposition(),
                ActivationDispositionV1::FirstActivation
            ) {
                let prepared_frame = read_frame(&mut parent_channel)?;
                let prepared = ProtectedFirstActivationPreparedV1::decode_frame(&prepared_frame)
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
                let commit_frame = Zeroizing::new(
                    commit
                        .encode_frame()
                        .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                );
                write_frame(&mut parent_channel, &commit_frame)?;
                controls.checkpoint(ActivationCheckpoint::AfterCommit)?;
                Some(pending)
            } else {
                None
            };

            let ready_frame = read_frame(&mut parent_channel)?;
            let ready = request.decode_ready(&ready_frame, &keys)?;
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
            let runtime_profile = request.runtime_profile(&ready, unix_millis()?, &keys)?;
            keys.forget_bootstrap_key();
            controls.checkpoint(ActivationCheckpoint::BeforeFinalPin)?;
            state_store.persist_stable_exact(ready.stable(), controls)?;
            controls.checkpoint(ActivationCheckpoint::AfterFinalPin)?;
            state_store.remove_pending()?;
            let activation = ready.into_process_activation(request)?;
            Ok(ProtectedBundledRuntimeProcess {
                child: child
                    .take()
                    .ok_or(ProtectedBundledRuntimeError::InvalidState)?,
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

        if result.is_err()
            && let Some(child) = child.as_mut()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
}
