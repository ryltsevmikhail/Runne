use std::os::fd::AsRawFd as _;

use runne_api::{CredentialServiceRejoinBinding, CredentialServiceSessionAuthenticator};

use super::{
    CredentialServiceRegistrationFacts, CredentialServiceSessionRegistrationError,
    ProtectedBundledRuntimeError, ProtectedBundledRuntimeProcess,
    ProtectedBundledRuntimeSupervisor, ProtectedProcessActivation,
    RegisteredCredentialServiceSession, register_credential_service_session_with_port, unix_millis,
};

const REJOIN_MAX_LIFETIME_MILLIS: u64 = 5_000;

pub struct CredentialServiceRejoinContext {
    configuration: runne_macos_xpc::CredentialServiceEndpointConfiguration,
    installed_generation: u64,
    join_attempt: u64,
    // Retain the authenticated parent-bounded lifetime; restart never renews it.
    parent_expiry: u64,
}

impl CredentialServiceRejoinContext {
    pub(super) fn from_registered(
        registered: &RegisteredCredentialServiceSession,
    ) -> Result<Self, ProtectedBundledRuntimeError> {
        let binding = registered.claim.binding();
        Ok(Self {
            configuration: registered
                .configuration
                .clone()
                .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?,
            installed_generation: binding.installed_generation(),
            join_attempt: binding.join_attempt(),
            parent_expiry: binding.expires_at_unix_millis(),
        })
    }

    fn matches(
        &self,
        binding: &CredentialServiceRejoinBinding,
        process: &ProtectedBundledRuntimeProcess,
        now: u64,
    ) -> bool {
        let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
            return false;
        };
        let enrollment = owned.enrollment_binding();
        let Some(next_attempt) = self.join_attempt.checked_add(1) else {
            return false;
        };
        binding.protected_session_id() == *owned.session_id()
            && binding.daemon_authority_generation() == owned.launch_generation()
            && binding.runtime_generation() == owned.launch_generation()
            && binding.supervisor_generation() == enrollment.desktop_supervisor_generation()
            && binding.installed_generation() == self.installed_generation
            && binding.installation_owner() == *enrollment.installation_identity_digest()
            && binding.release_binding() == *enrollment.release_tuple_digest()
            && binding.join_attempt() == next_attempt
            && binding.expires_at_unix_millis() <= self.parent_expiry
            && binding.expires_at_unix_millis() > now
            && binding.expires_at_unix_millis().saturating_sub(now) <= REJOIN_MAX_LIFETIME_MILLIS
    }
}

/// Native service challenge prepared from one authenticated daemon rejoin request.
pub struct PreparedCredentialServiceRejoin {
    configuration: runne_macos_xpc::CredentialServiceEndpointConfiguration,
    authenticator: CredentialServiceSessionAuthenticator,
    facts: CredentialServiceRegistrationFacts,
}

impl PreparedCredentialServiceRejoin {
    /// Completes the service challenge without holding the supervisor lock.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for epoch skew, XPC rejection, or an invalid acknowledgement.
    pub async fn register(
        self,
    ) -> Result<RegisteredCredentialServiceSession, ProtectedBundledRuntimeError> {
        let client =
            runne_macos_xpc::CredentialServiceDesktopXpcClient::connect(self.configuration.clone())
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        self.register_with_port(&client).await
    }

    pub(in crate::protected_runtime) async fn register_with_port(
        self,
        port: &impl runne_platform_ports::credential_service::CredentialServiceDesktopPort,
    ) -> Result<RegisteredCredentialServiceSession, ProtectedBundledRuntimeError> {
        let mut registered =
            register_credential_service_session_with_port(port, self.authenticator, self.facts)
                .await
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        registered.configuration = Some(self.configuration);
        Ok(registered)
    }
}

impl ProtectedBundledRuntimeSupervisor {
    /// Takes at most one authenticated rejoin request without blocking the monitor.
    ///
    /// # Errors
    ///
    /// Rejects malformed, expired, or ownership-skewed requests.
    pub fn prepare_pending_credential_service_rejoin(
        &mut self,
    ) -> Result<Option<PreparedCredentialServiceRejoin>, ProtectedBundledRuntimeError> {
        if self.state != super::super::BundledRuntimeLifecycleState::Ready
            || self.pending_profile.is_some()
        {
            return Ok(None);
        }
        if self.credential_service_rejoin.is_none() {
            return Ok(None);
        }
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let Some(frame) = pending_frame(process)? else {
            return Ok(None);
        };
        self.prepare_received_credential_service_rejoin(&frame)
            .map(Some)
    }

    pub(in crate::protected_runtime) fn prepare_received_credential_service_rejoin(
        &self,
        frame: &[u8],
    ) -> Result<PreparedCredentialServiceRejoin, ProtectedBundledRuntimeError> {
        if self.state != super::super::BundledRuntimeLifecycleState::Ready
            || self.pending_profile.is_some()
        {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let context = self
            .credential_service_rejoin
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let process = self
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let now = unix_millis().map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let required =
            CredentialServiceSessionAuthenticator::from_protected_activation(&process.keys)
                .decode_and_verify_rejoin(frame, now)
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if !context.matches(required.binding(), process, now) {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let facts = CredentialServiceRegistrationFacts::from_rejoin(
            required.binding(),
            context.parent_expiry,
        )
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let configuration = context.configuration.clone();
        Ok(PreparedCredentialServiceRejoin {
            configuration,
            authenticator: CredentialServiceSessionAuthenticator::from_protected_activation(
                &process.keys,
            ),
            facts,
        })
    }

    /// Sends the exact rejoin claim and acknowledgement to the owned daemon.
    ///
    /// # Errors
    ///
    /// Returns a closed channel or ownership failure.
    pub fn confirm_credential_service_rejoin(
        &mut self,
        registered: RegisteredCredentialServiceSession,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        self.confirm_credential_service_session(registered)
    }
}

#[cfg(feature = "test-support")]
pub(in crate::protected_runtime) fn test_rejoin_context(
    parent_expiry: u64,
) -> CredentialServiceRejoinContext {
    use runne_macos_xpc::{
        CredentialServiceEndpointConfiguration, CredentialServiceEndpointRole,
        CredentialServicePeerRequirement,
    };
    let requirement = |identifier: &str, hash: &str| {
        CredentialServicePeerRequirement::new(format!(
        "identifier \"{identifier}\" and anchor apple generic and certificate leaf[subject.OU] = \"758F9Z45SR\" and cdhash H\"{hash}\"",
    )).unwrap()
    };
    let role = CredentialServiceEndpointRole::Desktop;
    CredentialServiceRejoinContext {
        configuration: CredentialServiceEndpointConfiguration::new(
            role,
            role.endpoint_name(),
            requirement("com.runne.credential-service", &"1".repeat(40)),
            requirement("com.runne.desktop", &"2".repeat(40)),
        )
        .unwrap(),
        installed_generation: 1,
        join_attempt: 1,
        parent_expiry,
    }
}

impl CredentialServiceRegistrationFacts {
    fn from_rejoin(
        binding: &CredentialServiceRejoinBinding,
        parent_expiry: u64,
    ) -> Result<Self, CredentialServiceSessionRegistrationError> {
        if binding.expires_at_unix_millis() > parent_expiry {
            return Err(CredentialServiceSessionRegistrationError::InvalidFacts);
        }
        let mut facts = Self::new(
            binding.protected_session_id(),
            binding.daemon_authority_generation(),
            binding.runtime_generation(),
            binding.supervisor_generation(),
            binding.installed_generation(),
            binding.installation_owner(),
            binding.release_binding(),
            binding.join_attempt(),
            parent_expiry,
        )?;
        facts.exchange_deadline = Some(binding.expires_at_unix_millis());
        Ok(facts)
    }
}

fn pending_frame(
    process: &mut ProtectedBundledRuntimeProcess,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, ProtectedBundledRuntimeError> {
    let mut byte = [0_u8; 1];
    match nix::sys::socket::recv(
        process.channel.as_raw_fd(),
        &mut byte,
        nix::sys::socket::MsgFlags::MSG_PEEK | nix::sys::socket::MsgFlags::MSG_DONTWAIT,
    ) {
        Ok(0) => Err(ProtectedBundledRuntimeError::ProtectedChannelUnavailable),
        Ok(_) => super::super::read_frame(&mut process.channel).map(Some),
        Err(nix::errno::Errno::EAGAIN) => Ok(None),
        Err(_) => Err(ProtectedBundledRuntimeError::ProtectedChannelUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejoin_facts_preserve_parent_expiry_beyond_exchange_deadline() {
        let binding = CredentialServiceRejoinBinding::new(
            [9; 16],
            [1, 1, 1, 1, 1, 1, 0x70, 1, 0x80, 1, 1, 1, 1, 1, 1, 1],
            3,
            3,
            4,
            5,
            [6; 32],
            [7; 32],
            2,
            10_000,
        )
        .unwrap();
        let facts = CredentialServiceRegistrationFacts::from_rejoin(&binding, 480_100).unwrap();

        assert_eq!(facts.exchange_deadline, Some(10_000));
        assert!(CredentialServiceRegistrationFacts::from_rejoin(&binding, 9_999).is_err());

        let accepted = facts.binding([9; 16], [8; 16]).unwrap();
        assert_eq!(accepted.service_epoch(), &[9; 16]);
        assert_eq!(accepted.expires_at_unix_millis(), 480_100);
        assert_eq!(
            facts.binding([10; 16], [8; 16]).unwrap().service_epoch(),
            &[10; 16]
        );
    }
}
