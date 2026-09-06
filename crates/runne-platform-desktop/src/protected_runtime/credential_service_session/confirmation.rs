use super::{
    CredentialServiceSessionAuthenticator, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeProcess, ProtectedProcessActivation, RegisteredCredentialServiceSession,
    protected_control_frame, unix_millis,
};

impl ProtectedBundledRuntimeProcess {
    pub(super) fn confirm_credential_service_session(
        &mut self,
        registered: RegisteredCredentialServiceSession,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.graceful_requested {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let ProtectedProcessActivation::V3 { owned, .. } = &self.activation else {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        };
        let binding = registered.claim.binding();
        let enrollment = owned.enrollment_binding();
        if binding.protected_session_id() != owned.session_id()
            || binding.daemon_authority_generation() != owned.launch_generation()
            || binding.runtime_generation() != owned.launch_generation()
            || binding.supervisor_generation() != enrollment.desktop_supervisor_generation()
            || binding.installation_owner() != enrollment.installation_identity_digest()
            || binding.release_binding() != enrollment.release_tuple_digest()
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        // XPC registration ran outside the supervisor mutex. Recheck the exact
        // current launch, authenticator and expiry before any protected-channel write.
        let binding = binding.clone();
        let now = unix_millis().map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if registered
            .exchange_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let authenticator =
            CredentialServiceSessionAuthenticator::from_protected_activation(&self.keys);
        let claim = zeroize::Zeroizing::new(registered.claim.into_bytes());
        let acknowledgement = zeroize::Zeroizing::new(registered.acknowledgement.into_bytes());
        authenticator
            .decode_and_verify_registration_for(&claim, &binding, now)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        authenticator
            .decode_and_verify_ack_for(&acknowledgement, &binding, now)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let claim = protected_control_frame(claim.to_vec())?;
        let acknowledgement = protected_control_frame(acknowledgement.to_vec())?;
        let result = super::super::write_frame(&mut self.channel, &claim)
            .and_then(|()| super::super::write_frame(&mut self.channel, &acknowledgement));
        if result.is_err() {
            self.fence_ambiguous_transition();
        }
        result
    }
}
