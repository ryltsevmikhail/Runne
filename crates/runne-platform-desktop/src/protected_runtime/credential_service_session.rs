use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    ConfirmedInstalledNativeEnrollment, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeSupervisor, ProtectedProcessActivation,
};
use runne_api::{
    CREDENTIAL_SERVICE_MAX_FRAME_BYTES, CredentialServiceRegistrationAck,
    CredentialServiceRegistrationBinding, CredentialServiceRegistrationRequest,
    CredentialServiceSessionAuthenticator,
};

const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(5);

mod registration_exchange;
mod rejoin;
pub(super) use registration_exchange::register_credential_service_session_with_port;
pub use rejoin::CredentialServiceRejoinContext;
pub use rejoin::PreparedCredentialServiceRejoin;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CredentialServiceSessionRegistrationError {
    InvalidFacts,
    Transport,
    InvalidReply,
}

pub(super) struct CredentialServiceRegistrationFacts {
    protected_session_id: [u8; 16],
    daemon_authority_generation: u64,
    runtime_generation: u64,
    supervisor_generation: u64,
    installed_generation: u64,
    installation_owner: [u8; 32],
    release_binding: [u8; 32],
    join_attempt: u64,
    expires_at_unix_millis: u64,
}

pub struct PreparedCredentialServiceSessionRegistration {
    client: runne_macos_xpc::CredentialServiceDesktopXpcClient,
    configuration: runne_macos_xpc::CredentialServiceEndpointConfiguration,
    authenticator: CredentialServiceSessionAuthenticator,
    facts: CredentialServiceRegistrationFacts,
}

/// Service-verified registration evidence awaiting delivery to the exact daemon.
pub struct RegisteredCredentialServiceSession {
    claim: CredentialServiceRegistrationRequest,
    acknowledgement: CredentialServiceRegistrationAck,
    configuration: Option<runne_macos_xpc::CredentialServiceEndpointConfiguration>,
}

impl RegisteredCredentialServiceSession {
    #[must_use]
    pub fn service_epoch(&self) -> &[u8; 16] {
        self.acknowledgement.service_epoch()
    }

    #[must_use]
    pub const fn installed_generation(&self) -> u64 {
        self.acknowledgement.installed_generation()
    }
}

impl PreparedCredentialServiceSessionRegistration {
    /// # Errors
    ///
    /// Returns a closed registration failure when native service admission fails.
    pub async fn register(
        self,
    ) -> Result<RegisteredCredentialServiceSession, ProtectedBundledRuntimeError> {
        let mut registered = register_credential_service_session_with_port(
            &self.client,
            self.authenticator,
            self.facts,
        )
        .await
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        registered.configuration = Some(self.configuration);
        Ok(registered)
    }
}

impl ProtectedBundledRuntimeSupervisor {
    /// # Errors
    ///
    /// Rejects a release without one exact admitted credential-service tuple.
    pub fn prepare_credential_service_session_registration(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
    ) -> Result<PreparedCredentialServiceSessionRegistration, ProtectedBundledRuntimeError> {
        if self.state != super::BundledRuntimeLifecycleState::Ready
            || self.pending_profile.is_some()
        {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .prepare_credential_service_session_registration(confirmed)
    }

    /// # Errors
    ///
    /// Rejects an acknowledgement that does not match this live activation.
    pub fn confirm_credential_service_session(
        &mut self,
        registered: RegisteredCredentialServiceSession,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let context = CredentialServiceRejoinContext::from_registered(&registered)?;
        let result = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .confirm_credential_service_session(registered);
        if result.is_ok() {
            self.credential_service_rejoin = Some(context);
        } else {
            self.credential_service_rejoin = None;
        }
        result
    }
}

impl ProtectedBundledRuntimeProcess {
    fn prepare_credential_service_session_registration(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
    ) -> Result<PreparedCredentialServiceSessionRegistration, ProtectedBundledRuntimeError> {
        if self.graceful_requested {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let ProtectedProcessActivation::V3 { owned, .. } = &self.activation else {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        };
        let enrollment = owned.enrollment_binding();
        if confirmed.release_binding() != *enrollment.release_tuple_digest() {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let configuration = confirmed.desktop_credential_service_configuration()?;
        let client =
            runne_macos_xpc::CredentialServiceDesktopXpcClient::connect(configuration.clone())
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let generation = owned.launch_generation();
        let expires_at = unix_millis()
            .ok()
            .and_then(bounded_session_expiry_unix_millis)
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let facts = CredentialServiceRegistrationFacts::new(
            *owned.session_id(),
            generation,
            generation,
            enrollment.desktop_supervisor_generation(),
            confirmed.installed_generation(),
            *enrollment.installation_identity_digest(),
            *enrollment.release_tuple_digest(),
            1,
            expires_at,
        )
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        Ok(PreparedCredentialServiceSessionRegistration {
            client,
            configuration,
            authenticator: CredentialServiceSessionAuthenticator::from_protected_activation(
                &self.keys,
            ),
            facts,
        })
    }

    fn confirm_credential_service_session(
        &mut self,
        registered: RegisteredCredentialServiceSession,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.graceful_requested
            || !matches!(self.activation, ProtectedProcessActivation::V3 { .. })
        {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let claim = protected_control_frame(registered.claim.into_bytes())?;
        let acknowledgement = protected_control_frame(registered.acknowledgement.into_bytes())?;
        let result = super::write_frame(&mut self.channel, &claim)
            .and_then(|()| super::write_frame(&mut self.channel, &acknowledgement));
        if result.is_err() {
            self.fence_ambiguous_transition();
        }
        result
    }
}

pub(super) fn protected_control_frame(
    payload: Vec<u8>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtectedBundledRuntimeError> {
    if payload.is_empty() || payload.len() > CREDENTIAL_SERVICE_MAX_FRAME_BYTES {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    let mut frame = zeroize::Zeroizing::new(Vec::with_capacity(payload.len() + 4));
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend(payload);
    Ok(frame)
}

impl CredentialServiceRegistrationFacts {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        protected_session_id: [u8; 16],
        daemon_authority_generation: u64,
        runtime_generation: u64,
        supervisor_generation: u64,
        installed_generation: u64,
        installation_owner: [u8; 32],
        release_binding: [u8; 32],
        join_attempt: u64,
        expires_at_unix_millis: u64,
    ) -> Result<Self, CredentialServiceSessionRegistrationError> {
        CredentialServiceRegistrationBinding::new(
            [1; 16],
            protected_session_id,
            daemon_authority_generation,
            runtime_generation,
            supervisor_generation,
            installed_generation,
            installation_owner,
            release_binding,
            [1; 16],
            join_attempt,
            expires_at_unix_millis,
        )
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)?;
        Ok(Self {
            protected_session_id,
            daemon_authority_generation,
            runtime_generation,
            supervisor_generation,
            installed_generation,
            installation_owner,
            release_binding,
            join_attempt,
            expires_at_unix_millis,
        })
    }

    fn binding(
        &self,
        service_epoch: [u8; 16],
        challenge_nonce: [u8; 16],
    ) -> Result<CredentialServiceRegistrationBinding, CredentialServiceSessionRegistrationError>
    {
        CredentialServiceRegistrationBinding::new(
            service_epoch,
            self.protected_session_id,
            self.daemon_authority_generation,
            self.runtime_generation,
            self.supervisor_generation,
            self.installed_generation,
            self.installation_owner,
            self.release_binding,
            challenge_nonce,
            self.join_attempt,
            self.expires_at_unix_millis,
        )
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)
    }
}

pub(super) fn unix_millis() -> Result<u64, CredentialServiceSessionRegistrationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)?
        .as_millis()
        .try_into()
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)
}

pub(super) fn bounded_session_expiry_unix_millis(now: u64) -> Option<u64> {
    u64::try_from(runne_api::PROTECTED_BUNDLED_SESSION_RENEW_AFTER.as_millis())
        .ok()
        .and_then(|ttl| now.checked_add(ttl))
}
