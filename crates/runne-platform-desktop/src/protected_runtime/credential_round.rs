use super::{
    BundledRuntimeLifecycleState, EnrollmentBrokerFacts, ProtectedActivationKeys,
    ProtectedBundledRuntimeError, ProtectedBundledRuntimeProcess,
    ProtectedBundledRuntimeSupervisor, ProtectedChannel, ProtectedProcessActivation, random_nonce,
    read_frame, write_frame,
};
use runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3;
mod interleaved;
#[cfg(feature = "test-support")]
pub(super) use interleaved::begin;

fn exchange(
    channel: &mut ProtectedChannel,
    keys: &ProtectedActivationKeys,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> Result<EnrollmentBrokerFacts, ProtectedBundledRuntimeError> {
    let mut codec = runne_api::ProtectedCredentialRoundCodec::new(keys, owned);
    let nonce = random_nonce().ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    let request = codec
        .encode_request(nonce)
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    write_frame(channel, &request)?;
    let facts = codec
        .decode_offer(&read_frame(channel)?)
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    let accept = codec
        .encode_accept()
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    write_frame(channel, &accept)?;
    Ok(EnrollmentBrokerFacts::new(
        facts.channel_binding(),
        facts.publication_key(),
    ))
}

impl ProtectedBundledRuntimeSupervisor {
    /// Starts a fresh V3 exchange after terminal observation and session renewal.
    /// The native owner must retain runtime/updater leases and reap the previous writer first.
    /// Service registration must follow before a new enrollment/recovery Request.
    ///
    /// # Errors
    /// Rejects absent terminal evidence or an unchanged session; fences ambiguous exchanges.
    pub fn begin_next_protected_credential_round(
        &mut self,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let (owned, facts) = process.v3_enrollment_facts()?;
        if process.graceful_requested
            || facts.terminal_session.is_none()
            || facts.terminal_session == Some(*owned.session_id())
        {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        // No retry may reuse old facts after any part of the new transcript.
        process.enrollment_broker_facts = None;
        let result = exchange(&mut process.channel, &process.keys, &owned);
        match result {
            Ok(facts) => {
                process.enrollment_broker_facts = Some(facts);
                self.credential_service_rejoin = None;
                Ok(())
            }
            Err(error) => {
                process.fence_ambiguous_transition();
                Err(error)
            }
        }
    }
}

impl ProtectedBundledRuntimeProcess {
    pub(super) fn record_enrollment_terminal(
        &mut self,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let ProtectedProcessActivation::V3 { owned, .. } = &self.activation else {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        };
        let facts = self
            .enrollment_broker_facts
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        facts.terminal_session = Some(*owned.session_id());
        Ok(())
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests;
