// Desktop half of the dedicated protected remote quota verification operation.

use runne_api::{
    ProviderCredentialOperationKindV2, ProviderCredentialVerifyIntentBinding,
    ProviderCredentialVerificationKindV2,
};

use enrollment_lifecycle_facts::verification_command_context;

impl ProtectedBundledRuntimeSupervisor {
    /// Authenticates and executes one native-approved remote quota read.
    ///
    /// # Errors
    ///
    /// Returns `InvalidState` unless the supervisor is `Ready` with no pending
    /// profile and the request asks for a remote verification, and returns a
    /// closed channel or ownership failure when the authenticated daemon
    /// exchange does not match the protected session.
    pub fn begin_protected_credential_verification(
        &mut self,
        request: NativeProtectedCredentialVerificationBegin,
    ) -> Result<PreparedProtectedCredentialVerification, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .begin_protected_credential_verification(request)
    }
}

impl ProtectedBundledRuntimeProcess {
    fn begin_protected_credential_verification(
        &mut self,
        request: NativeProtectedCredentialVerificationBegin,
    ) -> Result<PreparedProtectedCredentialVerification, ProtectedBundledRuntimeError> {
        let NativeProtectedCredentialVerificationBegin {
            command,
            native_confirmation,
        } = request;
        if command.verification_kind() != ProviderCredentialVerificationKindV2::Remote {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let (owned, facts) = self.v3_enrollment_facts()?;
        let now = unix_millis()?;
        let expires = now
            .checked_add(CONTROL_TTL_MILLIS)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let context = verification_command_context(&command)?;
        let intent = ProviderCredentialVerifyIntentBinding::new(&command, &context);
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
        let admission = authenticator
            .decode_authenticated_admission(&read_frame(&mut self.channel)?, &verified, 1, now)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        require_admission(&admission, &owned, native_confirmation, facts)?;
        let codec = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(
            &self.keys,
        );
        let verify = codec
            .encode_desktop_verify(&command, 1)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        write_frame(&mut self.channel, &verify)?;
        let snapshot = codec
            .decode_daemon_snapshot(&read_frame(&mut self.channel)?, 0)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if snapshot.operation_kind() != ProviderCredentialOperationKindV2::VerifyRemote
            || !matches!(
                snapshot.state(),
                ProviderCredentialOperationStateV2::Completed
                    | ProviderCredentialOperationStateV2::Failed
                    | ProviderCredentialOperationStateV2::Expired
                    | ProviderCredentialOperationStateV2::Cancelled
                    | ProviderCredentialOperationStateV2::Tombstoned
            )
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        self.record_enrollment_terminal()?;
        Ok(PreparedProtectedCredentialVerification {
            snapshot,
            terminal: true,
        })
    }
}
