// Desktop-owned protected Request/Begin/relay lifecycle on the entered V3 channel.

use runne_api::{
    ProtectedCredentialEnrollmentAuthenticator, ProtectedCredentialEnrollmentControlFrame,
    ProtectedCredentialEnrollmentLifecycleCodec, ProtectedCredentialEnrollmentRequestBinding,
    ProviderCredentialBeginIntentBinding,
    ProviderCredentialOperationStateV2,
    protected_credential_broker_evidence_binding, protected_credential_native_intent_digest,
};
use enrollment_lifecycle_facts::{command_context, require_admission};

const CONTROL_TTL_MILLIS: u64 = 20_000;

impl ProtectedBundledRuntimeSupervisor {
    /// Fails a nonterminal enrollment through the authenticated V3 channel so
    /// the daemon consumes its exact writer-kill authority before desktop reap.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when no exact protected process is retained.
    pub fn abort_protected_credential_enrollment(
        &mut self,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        process.abort_protected_credential_enrollment()
    }

    /// Returns an opaque binding to the actual rotated V3 session.
    ///
    /// # Errors
    ///
    /// Returns a closed failure outside authenticated V3 Ready state.
    pub fn current_credential_enrollment_intent_binding(
        &self,
    ) -> Result<[u8; 32], ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .credential_enrollment_intent_binding()
    }

    /// Authenticates Request/Admission and begins one durable Prepared operation.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for stale lifecycle or protected evidence.
    pub fn begin_protected_credential_enrollment(
        &mut self,
        request: NativeProtectedCredentialEnrollmentBegin,
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .begin_protected_credential_enrollment(request)
    }

    /// Reads the exact claimed relay only after the writer handoff completed.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for wrong lifecycle, sequence, or relay bytes.
    pub fn receive_credential_secret_relay(
        &mut self,
        enrollment: &mut PreparedProtectedCredentialEnrollment,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .receive_credential_secret_relay(enrollment)
    }

    /// Acknowledges the exact consumed relay and reads terminal safe readback.
    ///
    /// # Errors
    ///
    /// Returns a closed failure unless exact relay consumption precedes readback.
    pub fn finish_protected_credential_enrollment(
        &mut self,
        enrollment: &mut PreparedProtectedCredentialEnrollment,
        relay: &[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES],
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .finish_protected_credential_enrollment(enrollment, relay)
    }
}

impl ProtectedBundledRuntimeProcess {
    fn abort_protected_credential_enrollment(
        &mut self,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        // A Shutdown while enrollment is nonterminal is rejected by the daemon
        // only after its V3 loop terminates the exact retained writer. EOF is
        // therefore the acknowledgement for this fail-closed cleanup purpose.
        self.request_graceful_stop()
    }

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

    fn begin_protected_credential_enrollment(
        &mut self,
        request: NativeProtectedCredentialEnrollmentBegin,
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        let NativeProtectedCredentialEnrollmentBegin {
            command,
            native_confirmation,
        } = request;
        let (owned, facts) = self.v3_enrollment_facts()?;
        let now = unix_millis()?;
        let expires = now
            .checked_add(CONTROL_TTL_MILLIS)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let context = command_context(&command)?;
        let intent = ProviderCredentialBeginIntentBinding::new(&command, &context);
        let binding = ProtectedCredentialEnrollmentRequestBinding::new(
            *owned.launch_authority_id(),
            *owned.session_id(),
            *owned.daemon_instance_id(),
            owned.launch_generation(),
            owned.enrollment_binding().desktop_supervisor_generation(),
            *uuid::Uuid::now_v7().as_bytes(),
            *owned.enrollment_binding().release_tuple_digest(),
            *owned.enrollment_binding().desktop_peer_binding_digest(),
            native_confirmation,
            protected_credential_broker_evidence_binding(
                *owned.enrollment_binding().release_tuple_digest(),
                facts.binding(),
                facts.publication_public_key(),
            ),
            protected_credential_native_intent_digest(command.native_intent_id()),
            *intent.action_provider_revision_digest(),
            *intent.command_identity_digest(),
            now,
            expires,
        )
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let authenticator = ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(
            &self.keys,
        );
        let signed = authenticator
            .issue_request(binding, 1)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let frame = ProtectedCredentialEnrollmentControlFrame::Request(signed).encode_frame();
        let verified = authenticator
            .decode_authenticated_request(&frame, 0, now)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        write_frame(&mut self.channel, &frame)?;
        let admission = read_frame(&mut self.channel)?;
        let admission = authenticator
            .decode_authenticated_admission(&admission, &verified, 1, now)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        require_admission(&admission, &owned, native_confirmation, facts)?;
        let codec = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(
            &self.keys,
        );
        let begin = codec
            .encode_desktop_begin(&command, 1)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        write_frame(&mut self.channel, &begin)?;
        let snapshot = codec
            .decode_daemon_snapshot(&read_frame(&mut self.channel)?, 0)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let terminal = snapshot.state().terminal();
        if !terminal
            && (snapshot.state() != ProviderCredentialOperationStateV2::Prepared
                || snapshot.broker_rendezvous_id().is_none())
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        Ok(PreparedProtectedCredentialEnrollment {
            codec,
            snapshot,
            relay: None,
            relay_taken: false,
            terminal,
        })
    }

    fn receive_credential_secret_relay(
        &mut self,
        enrollment: &mut PreparedProtectedCredentialEnrollment,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if enrollment.relay.is_some() || enrollment.relay_taken || enrollment.terminal {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let relay = enrollment
            .codec
            .decode_daemon_relay(&read_frame(&mut self.channel)?, 1)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        enrollment.relay = Some(
            relay
                .try_into()
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?,
        );
        enrollment.relay_taken = false;
        Ok(())
    }

    fn finish_protected_credential_enrollment(
        &mut self,
        enrollment: &mut PreparedProtectedCredentialEnrollment,
        relay: &[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES],
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if !relay_ack_allowed(
            enrollment.relay_taken,
            enrollment.terminal,
            enrollment.relay.as_ref(),
            relay,
        ) {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let ack = enrollment
            .codec
            .encode_desktop_relay_ack(relay, 2)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        write_frame(&mut self.channel, &ack)?;
        let terminal = enrollment
            .codec
            .decode_daemon_snapshot(&read_frame(&mut self.channel)?, 2)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if !matches!(
            terminal.state(),
            ProviderCredentialOperationStateV2::Completed
                | ProviderCredentialOperationStateV2::Failed
                | ProviderCredentialOperationStateV2::Expired
                | ProviderCredentialOperationStateV2::Cancelled
                | ProviderCredentialOperationStateV2::Tombstoned
        ) {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        enrollment.snapshot = terminal;
        enrollment.relay = None;
        enrollment.relay_taken = true;
        enrollment.terminal = true;
        Ok(())
    }

    fn v3_enrollment_facts(
        &self,
    ) -> Result<(runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, EnrollmentBrokerFacts), ProtectedBundledRuntimeError> {
        let ProtectedProcessActivation::V3 { owned, .. } = &self.activation else {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        };
        Ok((owned.clone(), self.enrollment_broker_facts.ok_or(ProtectedBundledRuntimeError::InvalidState)?))
    }
}

fn relay_ack_allowed(
    relay_taken: bool,
    terminal: bool,
    retained: Option<&[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES]>,
    provided: &[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES],
) -> bool {
    relay_taken && !terminal && retained == Some(provided)
}
