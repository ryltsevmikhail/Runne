use enrollment_lifecycle_facts::{command_context, require_admission};
use runne_api::{
    ProtectedCredentialEnrollmentAuthenticator,
    ProtectedCredentialEnrollmentControlFrame, ProtectedCredentialEnrollmentLifecycleCodec,
    ProtectedCredentialEnrollmentRequestBinding, ProviderCredentialBeginIntentBinding,
    ProviderCredentialOperationStateV2, protected_credential_broker_evidence_binding,
    protected_credential_native_intent_digest,
};
#[path = "enrollment_lifecycle/linux_relay_fd.rs"]
mod linux_relay_fd;

impl ProtectedBundledRuntimeSupervisor {
    /// Aborts the active Linux protected credential enrollment.
    ///
    /// # Errors
    /// Returns an error when there is no owned process or the daemon rejects
    /// the graceful stop request.
    pub fn abort_protected_credential_enrollment(
        &mut self,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        self.process.as_mut().ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .request_graceful_stop()
    }

    /// Returns the session binding for the currently running V3 credential enrollment.
    ///
    /// # Errors
    /// Returns an error unless the supervisor is ready with an owned V3 process.
    pub fn current_credential_enrollment_intent_binding(
        &self,
    ) -> Result<[u8; 32], ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process.as_ref().ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .credential_enrollment_intent_binding()
    }

    /// Starts a Linux protected credential enrollment operation.
    ///
    /// # Errors
    /// Returns an error when the supervisor is not ready or the daemon rejects
    /// the request.
    pub fn begin_protected_credential_enrollment(
        &mut self,
        request: NativeProtectedCredentialEnrollmentBegin,
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process.as_mut().ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .begin_linux_credential_enrollment(request)
    }

    /// Receives the protected lifecycle relay for a Linux credential operation.
    ///
    /// # Errors
    /// Returns an error when the supervisor or operation is not ready.
    pub fn receive_credential_secret_relay(
        &mut self,
        enrollment: &mut PreparedProtectedCredentialEnrollment,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process.as_mut().ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .receive_linux_credential_secret_relay(enrollment)
    }

    /// Completes Pair after the one-shot authenticated relay has been consumed.
    ///
    /// # Errors
    /// Returns an error when the operation state is invalid or the daemon rejects
    /// the relay or terminal response.
    pub fn finish_protected_credential_enrollment(
        &mut self,
        enrollment: &mut PreparedProtectedCredentialEnrollment,
        relay: &[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES],
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let process = self.process.as_mut().ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some()
            || !enrollment.relay_taken || enrollment.terminal
            || enrollment.relay.as_ref() != Some(relay)
        { return Err(ProtectedBundledRuntimeError::OwnershipMismatch); }
        let ack = enrollment.codec.encode_desktop_relay_ack(relay, 2)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        write_frame(&mut process.channel, &ack)?;
        let frame = read_frame(&mut process.channel)?;
        accept_linux_terminal(process, enrollment, &frame, false)
    }

    /// Completes a control-only Revoke operation.
    ///
    /// # Errors
    /// Returns an error when the operation state is invalid or the daemon rejects
    /// the terminal response.
    pub fn finish_control_only_credential_enrollment(
        &mut self,
        enrollment: &mut PreparedProtectedCredentialEnrollment,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let process = self.process.as_mut().ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some()
            || enrollment.relay.is_some() || enrollment.terminal
        { return Err(ProtectedBundledRuntimeError::OwnershipMismatch); }
        let frame = read_frame(&mut process.channel)?;
        accept_linux_terminal(process, enrollment, &frame, true)
    }
}

impl ProtectedBundledRuntimeProcess {
    fn credential_enrollment_intent_binding(
        &self,
    ) -> Result<[u8; 32], ProtectedBundledRuntimeError> {
        use sha2::Digest as _;
        let ProtectedProcessActivation::V3 { owned, .. } = &self.activation else {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        };
        let mut digest = sha2::Sha256::new();
        digest.update(b"gocode/provider-credential-enrollment/v3-intent-session/v1\0");
        digest.update(owned.launch_authority_id());
        digest.update(owned.session_id());
        digest.update(owned.daemon_instance_id());
        digest.update(owned.launch_generation().to_be_bytes());
        digest.update(owned.enrollment_binding().release_tuple_digest());
        Ok(digest.finalize().into())
    }

    fn begin_linux_credential_enrollment(
        &mut self,
        request: NativeProtectedCredentialEnrollmentBegin,
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        let (command, native_confirmation) = (request.command, request.native_confirmation);
        let ProtectedProcessActivation::V3 { owned, .. } = &self.activation else {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        };
        let facts = self.enrollment_broker_facts.ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let now = credential_enrollment_unix_wall_millis()?;
        let expires = now.checked_add(20_000).ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let context = command_context(&command)?;
        let intent = ProviderCredentialBeginIntentBinding::new(&command, &context);
        let binding = ProtectedCredentialEnrollmentRequestBinding::new(
            *owned.launch_authority_id(), *owned.session_id(), *owned.daemon_instance_id(),
            owned.launch_generation(), owned.enrollment_binding().desktop_supervisor_generation(),
            *uuid::Uuid::now_v7().as_bytes(), *owned.enrollment_binding().release_tuple_digest(),
            *owned.enrollment_binding().desktop_peer_binding_digest(), native_confirmation,
            protected_credential_broker_evidence_binding(*owned.enrollment_binding().release_tuple_digest(), facts.binding(), facts.publication_public_key()),
            protected_credential_native_intent_digest(command.native_intent_id()),
            *intent.action_provider_revision_digest(), *intent.command_identity_digest(), now, expires,
        ).map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let auth = ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&self.keys);
        let signed = auth.issue_request(binding, 1).map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let frame = ProtectedCredentialEnrollmentControlFrame::Request(signed).encode_frame();
        let verified = auth.decode_authenticated_request(&frame, 0, now).map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        write_frame(&mut self.channel, &frame)?;
        let admission = auth.decode_authenticated_admission(&read_frame(&mut self.channel)?, &verified, 1, now)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        require_admission(&admission, owned, native_confirmation, facts)?;
        let codec = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&self.keys);
        let begin = codec.encode_desktop_begin(&command, 1).map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        write_frame(&mut self.channel, &begin)?;
        let snapshot = codec.decode_daemon_snapshot(&read_frame(&mut self.channel)?, 0)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let terminal = snapshot.state().terminal();
        if terminal { self.record_linux_enrollment_terminal()?; }
        if !terminal && (snapshot.state() != ProviderCredentialOperationStateV2::Prepared || snapshot.broker_rendezvous_id().is_none()) {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        Ok(PreparedProtectedCredentialEnrollment { codec, snapshot, relay: None, relay_taken: false, relay_fd_taken: false, relay_lifecycle_frame: None, terminal })
    }

    fn receive_linux_credential_secret_relay(
        &mut self,
        enrollment: &mut PreparedProtectedCredentialEnrollment,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if enrollment.relay.is_some() || enrollment.relay_taken || enrollment.terminal { return Err(ProtectedBundledRuntimeError::InvalidState); }
        let frame = read_frame(&mut self.channel)?;
        let relay = enrollment.codec.decode_daemon_relay(&frame, 1)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        enrollment.relay = Some(relay.try_into().map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?);
        enrollment.relay_lifecycle_frame = Some(frame);
        Ok(())
    }

    fn record_linux_enrollment_terminal(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        let ProtectedProcessActivation::V3 { owned, .. } = &self.activation else { return Err(ProtectedBundledRuntimeError::InvalidState); };
        self.enrollment_broker_facts.as_mut().ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?.terminal_session = Some(*owned.session_id());
        Ok(())
    }
}

fn accept_linux_terminal(
    process: &mut ProtectedBundledRuntimeProcess,
    enrollment: &mut PreparedProtectedCredentialEnrollment,
    frame: &[u8],
    control_only: bool,
) -> Result<(), ProtectedBundledRuntimeError> {
    let terminal = enrollment.codec.decode_daemon_snapshot(frame, if control_only { 1 } else { 2 })
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    if terminal.state() != ProviderCredentialOperationStateV2::Completed
        || terminal.operation_handle() != enrollment.snapshot.operation_handle()
        || terminal.operation_kind() != enrollment.snapshot.operation_kind()
        || terminal.provider_id() != enrollment.snapshot.provider_id()
        || (control_only && enrollment.relay.is_some())
        || (!control_only && !enrollment.relay_fd_taken)
    { return Err(ProtectedBundledRuntimeError::OwnershipMismatch); }
    process.record_linux_enrollment_terminal()?;
    enrollment.snapshot = terminal;
    enrollment.relay = None;
    enrollment.relay_lifecycle_frame = None;
    enrollment.relay_taken = true;
    enrollment.terminal = true;
    Ok(())
}

fn credential_enrollment_unix_wall_millis() -> Result<u64, ProtectedBundledRuntimeError> {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|v| u64::try_from(v.as_millis()).unwrap_or(u64::MAX))
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)
}
