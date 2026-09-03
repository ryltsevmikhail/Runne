use runne_api::{
    CredentialServiceRegistrationBinding, CredentialServiceRejoinBinding,
    CredentialServiceSessionAuthenticator, LaunchAuthorityError, ProtectedActivationKeys,
    ProtectedCredentialEnrollmentOwnedLaunchV3,
};
use runne_provider::CredentialServiceEpoch;

use super::ProtectedActivationChannel;

mod runtime_io;

pub(super) struct ExpectedCredentialServiceRegistration {
    protected_session_id: [u8; 16],
    daemon_authority_generation: u64,
    runtime_generation: u64,
    supervisor_generation: u64,
    installed_generation: u64,
    installation_owner: [u8; 32],
    release_binding: [u8; 32],
    join_attempt: u64,
    exact_service_epoch: Option<[u8; 16]>,
    exact_expiry: Option<u64>,
}

impl ExpectedCredentialServiceRegistration {
    pub(super) fn from_owned(
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        installed_generation: u64,
    ) -> Self {
        let enrollment = owned.enrollment_binding();
        Self {
            protected_session_id: *owned.session_id(),
            daemon_authority_generation: owned.launch_generation(),
            runtime_generation: owned.launch_generation(),
            supervisor_generation: enrollment.desktop_supervisor_generation(),
            installed_generation,
            installation_owner: *enrollment.installation_identity_digest(),
            release_binding: *enrollment.release_tuple_digest(),
            join_attempt: 1,
            exact_service_epoch: None,
            exact_expiry: None,
        }
    }

    #[cfg(test)]
    pub(super) fn from_binding(binding: &CredentialServiceRegistrationBinding) -> Self {
        Self {
            protected_session_id: *binding.protected_session_id(),
            daemon_authority_generation: binding.daemon_authority_generation(),
            runtime_generation: binding.runtime_generation(),
            supervisor_generation: binding.supervisor_generation(),
            installed_generation: binding.installed_generation(),
            installation_owner: *binding.installation_owner(),
            release_binding: *binding.release_binding(),
            join_attempt: binding.join_attempt(),
            exact_service_epoch: None,
            exact_expiry: None,
        }
    }

    pub(super) fn from_rejoin(binding: &CredentialServiceRejoinBinding) -> Self {
        Self {
            protected_session_id: binding.protected_session_id(),
            daemon_authority_generation: binding.daemon_authority_generation(),
            runtime_generation: binding.runtime_generation(),
            supervisor_generation: binding.supervisor_generation(),
            installed_generation: binding.installed_generation(),
            installation_owner: binding.installation_owner(),
            release_binding: binding.release_binding(),
            join_attempt: binding.join_attempt(),
            exact_service_epoch: Some(binding.service_epoch()),
            exact_expiry: Some(binding.expires_at_unix_millis()),
        }
    }

    fn matches(&self, binding: &CredentialServiceRegistrationBinding) -> bool {
        binding.protected_session_id() == &self.protected_session_id
            && binding.daemon_authority_generation() == self.daemon_authority_generation
            && binding.runtime_generation() == self.runtime_generation
            && binding.supervisor_generation() == self.supervisor_generation
            && binding.installed_generation() == self.installed_generation
            && binding.installation_owner() == &self.installation_owner
            && binding.release_binding() == &self.release_binding
            && binding.join_attempt() == self.join_attempt
            && self
                .exact_service_epoch
                .is_none_or(|epoch| binding.service_epoch() == &epoch)
            && self
                .exact_expiry
                .is_none_or(|expiry| binding.expires_at_unix_millis() == expiry)
    }
}

pub(crate) struct CredentialServiceRuntimeSession {
    authenticator: CredentialServiceSessionAuthenticator,
    binding: CredentialServiceRegistrationBinding,
    client: Option<runne_macos_xpc::CredentialServiceRuntimeXpcClient>,
    next_sequence: u64,
    missing_epoch: Option<runne_provider::CredentialServiceEpoch>,
}

impl CredentialServiceRuntimeSession {
    #[cfg(test)]
    pub(super) const fn binding(&self) -> &CredentialServiceRegistrationBinding {
        &self.binding
    }

    pub(super) fn supersedes(&self, old: &Self) -> bool {
        let candidate = &self.binding;
        let current = &old.binding;
        let Some(next_attempt) = current.join_attempt().checked_add(1) else {
            return false;
        };
        if candidate.installation_owner() != current.installation_owner()
            || candidate.join_attempt() != next_attempt
            || candidate.challenge_nonce() == current.challenge_nonce()
            || candidate.installed_generation() < current.installed_generation()
        {
            return false;
        }
        let release_is_current = candidate.installed_generation() > current.installed_generation()
            || candidate.release_binding() == current.release_binding();
        if !release_is_current {
            return false;
        }
        let same_runtime_rejoin = candidate.runtime_generation() == current.runtime_generation()
            && candidate.daemon_authority_generation() == current.daemon_authority_generation()
            && candidate.supervisor_generation() == current.supervisor_generation();
        let runtime_restart = candidate.runtime_generation() > current.runtime_generation()
            && candidate.daemon_authority_generation() > current.daemon_authority_generation()
            && candidate.supervisor_generation() >= current.supervisor_generation()
            && candidate.protected_session_id() != current.protected_session_id();
        same_runtime_rejoin || runtime_restart
    }

    pub(super) fn take_missing_epoch(&mut self) -> Option<runne_provider::CredentialServiceEpoch> {
        self.missing_epoch.take()
    }

    pub(super) fn prepare_rejoin_binding(
        &self,
        epoch: CredentialServiceEpoch,
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        expires_at_unix_millis: u64,
    ) -> Result<CredentialServiceRejoinBinding, LaunchAuthorityError> {
        let enrollment = owned.enrollment_binding();
        if owned.launch_generation() != self.binding.runtime_generation()
            || enrollment.desktop_supervisor_generation() != self.binding.supervisor_generation()
            || enrollment.installation_identity_digest() != self.binding.installation_owner()
            || enrollment.release_tuple_digest() != self.binding.release_binding()
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        CredentialServiceRejoinBinding::new(
            epoch.as_bytes(),
            *owned.session_id(),
            owned.launch_generation(),
            owned.launch_generation(),
            enrollment.desktop_supervisor_generation(),
            self.binding.installed_generation(),
            *self.binding.installation_owner(),
            *self.binding.release_binding(),
            self.binding
                .join_attempt()
                .checked_add(1)
                .ok_or(LaunchAuthorityError::InvalidContract)?,
            expires_at_unix_millis,
        )
        .map_err(|_| LaunchAuthorityError::InvalidContract)
    }
}

pub(super) fn accept_registration_frames(
    keys: &ProtectedActivationKeys,
    expected: &ExpectedCredentialServiceRegistration,
    claim_frame: &[u8],
    acknowledgement_frame: &[u8],
    now_unix_millis: u64,
) -> Result<CredentialServiceRuntimeSession, LaunchAuthorityError> {
    let authenticator = CredentialServiceSessionAuthenticator::from_protected_activation(keys);
    let verified = authenticator
        .decode_and_verify_registration(claim_frame)
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
    if !expected.matches(verified.binding()) {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    let binding = verified.binding().clone();
    authenticator
        .decode_and_verify_ack_for(acknowledgement_frame, &binding, now_unix_millis)
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
    Ok(CredentialServiceRuntimeSession {
        authenticator,
        binding,
        client: None,
        next_sequence: 0,
        missing_epoch: None,
    })
}

pub(super) fn receive_required_registration(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    now_unix_millis: u64,
) -> Result<Option<CredentialServiceRuntimeSession>, LaunchAuthorityError> {
    if installed.credential_service().is_none() {
        return Ok(None);
    }
    let expected =
        ExpectedCredentialServiceRegistration::from_owned(owned, installed.installed_generation());
    let claim = channel.read_control_frame()?;
    let acknowledgement = channel.read_control_frame()?;
    let mut session = accept_registration_frames(
        keys,
        &expected,
        registration_payload(&claim)?,
        registration_payload(&acknowledgement)?,
        now_unix_millis,
    )?;
    let configuration = installed
        .runtime_credential_service_configuration()
        .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
    session.client = Some(
        runne_macos_xpc::CredentialServiceRuntimeXpcClient::connect(configuration)
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?,
    );
    Ok(Some(session))
}

pub(super) fn receive_rejoin_registration(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    binding: &CredentialServiceRejoinBinding,
    configuration: runne_macos_xpc::CredentialServiceEndpointConfiguration,
    now_unix_millis: u64,
) -> Result<CredentialServiceRuntimeSession, LaunchAuthorityError> {
    let claim = channel.read_control_frame()?;
    let acknowledgement = channel.read_control_frame()?;
    let mut session = accept_registration_frames(
        keys,
        &ExpectedCredentialServiceRegistration::from_rejoin(binding),
        registration_payload(&claim)?,
        registration_payload(&acknowledgement)?,
        now_unix_millis,
    )?;
    session.client = Some(
        runne_macos_xpc::CredentialServiceRuntimeXpcClient::connect(configuration)
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?,
    );
    Ok(session)
}

pub(super) fn registration_payload(frame: &[u8]) -> Result<&[u8], LaunchAuthorityError> {
    if frame.len() < 5 || frame.len() > runne_api::CREDENTIAL_SERVICE_MAX_FRAME_BYTES + 4 {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    let length = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    ) as usize;
    if length == 0 || length != frame.len() - 4 {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    Ok(&frame[4..])
}
