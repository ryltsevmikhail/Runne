#[cfg(all(unix, feature = "desktop-protected"))]
fn permission_scope(
    host: &PermissionControlHost,
    principal: &runne_api::ApiPrincipalId,
    workspace_id: runne_domain::id::WorkspaceId,
) -> runne_application::permission_modes::PermissionScope {
    runne_application::permission_modes::PermissionScope {
        runtime_authority_id: host.store().runtime_authority_id().clone(),
        principal_id: principal.clone(),
        workspace_id,
    }
}

#[cfg(all(unix, feature = "desktop-protected"))]
fn permission_mode(
    mode: runne_api::PermissionModeSelectionV1,
) -> runne_application::permission_modes::PermissionMode {
    use runne_application::permission_modes::PermissionMode as AppMode;
    match mode {
        runne_api::PermissionModeSelectionV1::AskAlways => AppMode::AskAlways,
        runne_api::PermissionModeSelectionV1::RiskBased => AppMode::RiskBased,
        runne_api::PermissionModeSelectionV1::FullAccess => AppMode::FullAccess,
    }
}

#[cfg(all(unix, feature = "desktop-protected"))]
fn validate_owner_context(
    host: &PermissionControlHost,
    launch: &runne_store::store::ProtectedNativeLaunchContext,
    principal: &runne_api::ApiPrincipalId,
    context: &runne_api::PermissionControlContextV1,
    native_key_epoch: u64,
) -> Result<(), ()> {
    if context.runtime_authority != host.store().runtime_authority_id().0
        || context.stable_subject_digest
            != runne_api::permission_control_stable_subject_digest_v1(principal).map_err(|_| ())?
        || context.protected_launch_authority_id != *launch.launch_authority_id()
        || context.desktop_authority_id != *launch.desktop_host_instance_id()
        || context.daemon_instance_id != *launch.daemon_instance_id()
        || context.protected_session_id != *launch.protected_session_id().ok_or(())?
        || context.launch_generation != launch.launch_generation()
        || context.native_key_epoch != native_key_epoch
        || context.native_key_epoch != launch.key_epoch()
    {
        return Err(());
    }
    Ok(())
}

#[cfg(all(unix, feature = "desktop-protected"))]
struct ConsentVerifier<'a> {
    authenticator: runne_api::PermissionControlNativeAuthenticatorV1,
    context: &'a PermissionControlContextV1,
    consent: &'a PermissionControlModeConsentV1,
}

#[cfg(all(unix, feature = "desktop-protected"))]
impl runne_application::permission_modes::NativeModeConfirmationVerifierV2 for ConsentVerifier<'_> {
    fn verify(
        &self,
        _binding: &runne_application::permission_modes::NativeModeConfirmationBindingV2,
        proof_bytes: &[u8],
    ) -> Result<
        runne_domain::id::IntegrityDigest,
        runne_application::permission_modes::NativeModeConfirmationError,
    > {
        if proof_bytes != self.consent.warning_attestation.as_slice() {
            return Err(runne_application::permission_modes::NativeModeConfirmationError::Rejected);
        }
        self.authenticator
            .verify_mode_consent(self.context, self.consent)
            .map_err(|_| {
                runne_application::permission_modes::NativeModeConfirmationError::Rejected
            })?;
        Ok(runne_domain::id::IntegrityDigest::from_bytes(
            self.consent.issued_challenge_binding_digest,
        ))
    }
}

#[cfg(all(unix, feature = "desktop-protected"))]
impl runne_application::permission_modes::NativeChallengeVerifier for ConsentVerifier<'_> {
    fn verify(
        &self,
        binding: &runne_application::permission_modes::FullAccessChallengeBinding,
        proof_bytes: &[u8],
    ) -> Result<
        runne_domain::id::IntegrityDigest,
        runne_application::permission_modes::NativeChallengeError,
    > {
        use runne_application::permission_modes::{NativeChallengeError, PermissionMode};

        if binding.requested_mode != PermissionMode::FullAccess
            || proof_bytes != self.consent.warning_attestation.as_slice()
            || binding.challenge_binding_digest.as_bytes()
                != self.consent.issued_challenge_binding_digest.as_slice()
        {
            return Err(NativeChallengeError::Rejected);
        }
        self.authenticator
            .verify_mode_consent(self.context, self.consent)
            .map_err(|_| NativeChallengeError::Rejected)?;
        Ok(binding.challenge_binding_digest)
    }
}
