use super::*;

#[cfg(test)]
mod tests;

// Both values come from the live authenticated registration; only the operation
// deadline crosses the rejoin wire. The replacement claim/ACK MAC binds expiry.
pub(in crate::protected_activation) struct PreparedCredentialServiceRejoin {
    pub(in crate::protected_activation) binding: CredentialServiceRejoinBinding,
    expected: ExpectedCredentialServiceRegistration,
}

impl CredentialServiceRuntimeSession {
    pub(in crate::protected_activation) fn prepare_rejoin_binding(
        &self,
        epoch: CredentialServiceEpoch,
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        expires_at_unix_millis: u64,
    ) -> Result<PreparedCredentialServiceRejoin, LaunchAuthorityError> {
        let enrollment = owned.enrollment_binding();
        if owned.session_id() != self.binding.protected_session_id()
            || owned.launch_generation() != self.binding.runtime_generation()
            || enrollment.desktop_supervisor_generation() != self.binding.supervisor_generation()
            || enrollment.installation_identity_digest() != self.binding.installation_owner()
            || enrollment.release_tuple_digest() != self.binding.release_binding()
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let binding = CredentialServiceRejoinBinding::new(
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
            expires_at_unix_millis.min(self.binding.expires_at_unix_millis()),
        )
        .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        let expected = ExpectedCredentialServiceRegistration::from_rejoin(
            &binding,
            self.binding.expires_at_unix_millis(),
        );
        Ok(PreparedCredentialServiceRejoin { binding, expected })
    }
}

pub(in crate::protected_activation) fn receive_rejoin_registration(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    prepared: &PreparedCredentialServiceRejoin,
    configuration: runne_macos_xpc::CredentialServiceEndpointConfiguration,
    now_unix_millis: u64,
) -> Result<RejoinedCredentialService, LaunchAuthorityError> {
    let received = receipt::receive(
        channel,
        keys,
        &prepared.expected,
        now_unix_millis,
        interleaved::receive,
        receipt::now,
    )?;
    let mut session = received.session;
    session.client = Some(
        runne_macos_xpc::CredentialServiceRuntimeXpcClient::connect(configuration.clone())
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?,
    );
    session.configuration = Some(configuration);
    Ok(RejoinedCredentialService {
        session,
        deferred: received.deferred,
    })
}
