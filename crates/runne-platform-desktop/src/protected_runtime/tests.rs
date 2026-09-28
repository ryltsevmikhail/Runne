
impl ProtectedBundledRuntimeProcess {
    /// Moves the path-free, one-time bootstrap profile to the native caller.
    pub const fn take_runtime_profile(&mut self) -> Option<ProtectedBundledRuntimeProfile> {
        self.runtime_profile.take()
    }

    /// Returns the authenticated non-secret provider binding for V2 launches.
    #[must_use]
    pub const fn provider_activation(&self) -> Option<&ProviderActivationBindingV1> {
        #[cfg(not(any(unix, windows)))]
        {
            None
        }
        #[cfg(any(unix, windows))]
        {
            self.activation.provider_activation()
        }
    }

    /// Copies role-separated activation keys only for test-support leak audits.
    #[cfg(all(feature = "test-support", unix))]
    #[doc(hidden)]
    #[must_use]
    pub fn test_activation_key_material(
        &self,
    ) -> runne_api::ProtectedActivationKeyMaterialForTest {
        self.keys.test_material()
    }

    /// Drains captured child output after the audited child has exited.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn take_captured_output_for_test(
        &mut self,
    ) -> Result<(Vec<u8>, Vec<u8>), ProtectedBundledRuntimeError> {
        if self.status()? != BundledRuntimeProcessStatus::Exited {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut handle) = self.captured_stdout.take() {
            handle
                .read_to_end(&mut stdout)
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        }
        if let Some(mut handle) = self.captured_stderr.take() {
            handle
                .read_to_end(&mut stderr)
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        }
        Ok((stdout, stderr))
    }

    /// Confirms that a connected client represents the exact current owned
    /// launch and protected transport.
    #[must_use]
    pub fn matches_client(&self, client: &AuthenticatedRuntimeClient) -> bool {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = client;
            false
        }
        #[cfg(any(unix, windows))]
        {
            if client.transport_kind() != RuntimeTransportKind::ProtectedBundled {
                return false;
            }
            if let Some(matches) = self.activation.matches_v3_runtime_client(client) {
                return matches;
            }
            let (Some(owned_launch), Some(ready)) = (
                self.activation.compatibility_owned(),
                self.activation.compatibility_ready(),
            ) else {
                return false;
            };
            let session = client.session_info();
            session.profile_id == owned_launch.profile().profile_id()
                && session.schema_hash == hex::encode(owned_launch.profile().profile_hash())
                && session.authority_id == hex::encode(owned_launch.stable().authority_id())
                && session.principal_id == owned_launch.stable().principal_id()
                && session.event_log_lineage_id
                    == uuid::Uuid::from_bytes(*owned_launch.stable().lineage_id()).to_string()
                && session.daemon_instance_id
                    == uuid::Uuid::from_bytes(*owned_launch.daemon_instance_id()).to_string()
                && session.launch_generation == owned_launch.launch_generation()
                && session.session_id == hex::encode(owned_launch.session_id())
                && session.capability_digest
                    == hex::encode(owned_launch.profile().capability_digest())
                && session.certificate_sha256 == hex::encode(ready.certificate_sha256())
                && session
                    .capabilities
                    .iter()
                    .map(String::as_str)
                    .eq(PROTECTED_RUNTIME_CAPABILITIES.iter().copied())
        }
    }

    /// Polls only the child handle returned by the direct spawn.
    ///
    /// # Errors
    ///
    /// Returns a closed ownership or platform error if the handle cannot be
    /// observed.
    pub fn status(&mut self) -> Result<BundledRuntimeProcessStatus, ProtectedBundledRuntimeError> {
        #[cfg(not(any(unix, windows)))]
        {
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(any(unix, windows))]
        {
            self.child
                .try_wait()
                .map(|status| {
                    if status.is_some() {
                        BundledRuntimeProcessStatus::Exited
                    } else {
                        BundledRuntimeProcessStatus::Running
                    }
                })
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
        }
    }

    /// Requests orderly shutdown for the exact current owned launch.
    ///
    /// # Errors
    ///
    /// Returns a closed channel, proof, ownership, or shutdown failure.
    pub fn request_graceful_stop(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        #[cfg(not(any(unix, windows)))]
        {
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(any(unix, windows))]
        {
            if self.graceful_requested {
                return if self.graceful_acknowledged { Ok(()) } else {
                    Err(ProtectedBundledRuntimeError::ShutdownIncomplete)
                };
            }
            match &self.activation {
                ProtectedProcessActivation::V1 { owned, .. } => {
                    let mut shutdown = ProtectedShutdownV1::new(owned.clone());
                    shutdown.sign(&self.keys);
                    let frame = Zeroizing::new(
                        shutdown
                            .encode_frame()
                            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                    );
                    write_frame(&mut self.channel, &frame)?;
                    let acknowledgement_frame = read_frame(&mut self.channel)?;
                    let acknowledgement =
                        ProtectedShutdownAckV1::decode_frame(&acknowledgement_frame)
                            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
                    acknowledgement.verify_exact(owned, &self.keys)?;
                    if !acknowledgement.graceful() {
                        return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
                    }
                }
                ProtectedProcessActivation::V2 { owned, .. } => {
                    let mut shutdown = ProtectedShutdownV2::new(owned.clone());
                    shutdown.sign(&self.keys);
                    let frame = Zeroizing::new(
                        shutdown
                            .encode_frame()
                            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                    );
                    write_frame(&mut self.channel, &frame)?;
                    let acknowledgement_frame = read_frame(&mut self.channel)?;
                    let acknowledgement =
                        ProtectedShutdownAckV2::decode_frame(&acknowledgement_frame)
                            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
                    acknowledgement.verify_exact(owned, &self.keys)?;
                    if !acknowledgement.graceful() {
                        return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
                    }
                }
                ProtectedProcessActivation::V3 { owned, .. } => {
                    let mut shutdown =
                        runne_api::ProtectedCredentialEnrollmentShutdownV3::new(owned.clone());
                    shutdown.sign(&self.keys);
                    let frame = Zeroizing::new(
                        shutdown
                            .encode_frame()
                            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                    );
                    write_frame(&mut self.channel, &frame)?;
                    let acknowledgement_frame = read_frame(&mut self.channel)?;
                    if !self
                        .activation
                        .verify_v3_shutdown_ack(&acknowledgement_frame, &self.keys)?
                    {
                        return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
                    }
                }
                #[cfg(feature = "test-support")]
                ProtectedProcessActivation::Test { owned } => {
                    let mut shutdown = ProtectedShutdownV1::new(owned.clone());
                    shutdown.sign(&self.keys);
                    let frame = Zeroizing::new(
                        shutdown
                            .encode_frame()
                            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                    );
                    write_frame(&mut self.channel, &frame)?;
                    let acknowledgement = ProtectedShutdownAckV1::decode_frame(&read_frame(&mut self.channel)?)
                        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
                    acknowledgement.verify_exact(owned, &self.keys)?;
                    if !acknowledgement.graceful() {
                        return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
                    }
                }
            }
            self.graceful_requested = true;
            self.graceful_acknowledged = true;
            Ok(())
        }
    }

    /// Waits only for the exact owned child handle.
    ///
    /// # Errors
    ///
    /// Returns a closed ownership or platform error if status cannot be read.
    pub fn wait_for_exit(
        &mut self,
        timeout: Duration,
    ) -> Result<BundledRuntimeProcessStatus, ProtectedBundledRuntimeError> {
        let deadline = Instant::now() + timeout;
        loop {
            let status = self.status()?;
            if status == BundledRuntimeProcessStatus::Exited || Instant::now() >= deadline {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Forces only the process represented by the already-owned child handle.
    ///
    /// # Errors
    ///
    /// Returns a closed ownership or incomplete-shutdown failure.
    pub fn terminate(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        #[cfg(not(any(unix, windows)))]
        {
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(any(unix, windows))]
        {
            if self.status()? == BundledRuntimeProcessStatus::Exited {
                return Ok(());
            }
            self.child
                .kill()
                .map_err(|_| ProtectedBundledRuntimeError::ShutdownIncomplete)
        }
    }

    /// Returns the OS process ID of the exact owned child, test-support only.
    /// Used by fault-injection tests that must SIGKILL the daemon from outside
    /// the owned graceful-shutdown channel (commit-before-ACK evidence).
    #[cfg(all(feature = "test-support", unix))]
    #[doc(hidden)]
    #[must_use]
    pub fn test_owned_child_id(&self) -> u32 {
        self.child.id()
    }
}

impl ProtectedBundledRuntimeSupervisor {
    /// Returns the OS process ID of the supervisor's running child,
    /// test-support only: the D1.6 kill matrix SIGKILLs the exact owned
    /// daemon at an armed pipeline boundary (see `test_owned_child_id`).
    #[cfg(all(feature = "test-support", unix))]
    #[doc(hidden)]
    #[must_use]
    pub fn test_owned_child_id(&self) -> u32 {
        self.process
            .as_ref()
            .expect("supervised process is running")
            .test_owned_child_id()
    }

    /// Waits until the supervised child exits, test-support only: the kill
    /// matrix must reap the SIGKILLed daemon before relaunching on the same
    /// durable root (same contract as `ProtectedBundledRuntimeProcess`).
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_wait_for_exit(
        &mut self,
        timeout: Duration,
    ) -> Result<BundledRuntimeProcessStatus, ProtectedBundledRuntimeError> {
        match self.process.as_mut() {
            Some(process) => process.wait_for_exit(timeout),
            None => Ok(BundledRuntimeProcessStatus::Exited),
        }
    }

    /// Takes the captured daemon output for diagnosis, test-support only.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_take_captured_output(&mut self) -> Option<String> {
        let (stdout, stderr) = self
            .process
            .as_mut()
            .expect("supervised process is running")
            .take_captured_output_for_test()
            .ok()?;
        Some(format!(
            "--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        ))
    }
}
