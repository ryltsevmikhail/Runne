use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    ConfirmedInstalledNativeEnrollment, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeSupervisor, ProtectedProcessActivation,
};
use runne_api::{
    CredentialServiceRegistrationAck, CredentialServiceRegistrationBinding,
    CredentialServiceRegistrationRequest, CredentialServiceSessionAuthenticator,
};

const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(5);

mod registration_exchange;
pub(super) use registration_exchange::register_credential_service_session_with_port;

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
    authenticator: CredentialServiceSessionAuthenticator,
    facts: CredentialServiceRegistrationFacts,
}

/// Service-verified registration evidence awaiting delivery to the exact daemon.
pub struct RegisteredCredentialServiceSession {
    claim: CredentialServiceRegistrationRequest,
    acknowledgement: CredentialServiceRegistrationAck,
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
        register_credential_service_session_with_port(&self.client, self.authenticator, self.facts)
            .await
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
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
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .confirm_credential_service_session(registered)
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
        let client = runne_macos_xpc::CredentialServiceDesktopXpcClient::connect(configuration)
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
        let result = super::write_frame(&mut self.channel, &registered.claim.into_bytes())
            .and_then(|()| {
                super::write_frame(&mut self.channel, &registered.acknowledgement.into_bytes())
            });
        if result.is_err() {
            self.fence_ambiguous_transition();
        }
        result
    }
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
