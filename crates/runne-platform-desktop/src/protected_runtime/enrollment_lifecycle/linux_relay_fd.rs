use super::{
    BundledRuntimeLifecycleState, PreparedProtectedCredentialEnrollment,
    ProtectedBundledRuntimeError, ProtectedBundledRuntimeProcess,
    ProtectedBundledRuntimeSupervisor,
};

use crate::provider_credential_broker::LinuxAuthenticatedPairSecretRelay;
use runne_api::LinuxPairSecretRelayOfferAuthenticator;

impl ProtectedBundledRuntimeSupervisor {
    /// Receives the daemon-owned one-shot Pair writer FD for the already
    /// validated relay retained in `enrollment`.
    ///
    /// # Errors
    ///
    /// Fails closed outside Ready, without exact V3 prelude facts, after reuse,
    /// or when the ancillary transfer does not match this lifecycle relay.
    pub fn receive_linux_pair_secret_relay_fd(
        &mut self,
        enrollment: &mut PreparedProtectedCredentialEnrollment,
    ) -> Result<LinuxAuthenticatedPairSecretRelay, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .receive_linux_pair_secret_relay_fd(enrollment)
    }
}

impl ProtectedBundledRuntimeProcess {
    fn receive_linux_pair_secret_relay_fd(
        &self,
        enrollment: &mut PreparedProtectedCredentialEnrollment,
    ) -> Result<LinuxAuthenticatedPairSecretRelay, ProtectedBundledRuntimeError> {
        if enrollment.relay_fd_taken || enrollment.terminal {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let relay_frame = *enrollment
            .relay
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        enrollment.relay_fd_taken = true;
        let facts = self
            .enrollment_broker_facts
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let authenticator =
            LinuxPairSecretRelayOfferAuthenticator::from_protected_activation(&self.keys);
        LinuxAuthenticatedPairSecretRelay::receive_linux_over_protected_stream(
            &self.channel,
            &authenticator,
            &relay_frame,
            &facts.binding(),
            &facts.publication_public_key(),
        )
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
    }
}
