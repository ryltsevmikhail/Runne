// Desktop half of the broker writer handoff over the entered V3 channel.
//
// The desktop drives three strictly ordered purposes on the already
// authenticated channel: the writer endpoint transfer, the writer evidence,
// and the kill exchange. Each purpose offers one daemon-owned socket half over
// the protected channel and then completes its fixed native exchange on that
// dedicated half. Any mismatch poisons the whole transport: the daemon loop
// fails closed and this process kills and reaps the owned daemon.

#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "protected-channel-integration"
))]
use runne_api::{ProviderCredentialBrokerHandoffContext, ProviderCredentialBrokerHandoffFrame};

/// Closed native writer launch profile. Only Pair may receive a secret relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialWriterHandoffMode {
    /// Installs fd3 and retains one authenticated secret relay.
    Pair,
    /// Installs no fd3 and exposes no secret relay.
    ControlOnly,
}

/// Desktop-held state after the daemon acknowledged the kill exchange.
#[cfg(target_os = "macos")]
pub struct CredentialWriterHandoff {
    owner: Option<crate::provider_credential_broker::MacOsWriterReapOnlyOwner>,
    pair_relay: Option<crate::provider_credential_broker::MacOsAuthenticatedPairSecretRelay>,
}

#[cfg(target_os = "macos")]
impl CredentialWriterHandoff {
    /// Takes the one-shot secret relay only when this handoff was created for Pair.
    pub const fn take_pair_secret_relay(
        &mut self,
    ) -> Option<crate::provider_credential_broker::MacOsAuthenticatedPairSecretRelay> {
        self.pair_relay.take()
    }

    /// Reaps the exact writer after the daemon owns its kill authority.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the retained writer cannot be reaped.
    pub fn reap_exact_writer(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        self.reap_exact_writer_bounded(std::time::Duration::from_secs(2))
    }

    /// Performs one bounded exact-child reap attempt for managed maintenance.
    ///
    /// # Errors
    ///
    /// Returns a closed failure while retaining the exact wait owner.
    pub fn reap_exact_writer_bounded(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let Some(owner) = self.owner.as_mut() else {
            return Ok(());
        };
        owner
            .reap_exact_writer_bounded(timeout)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        self.owner = None;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl std::fmt::Debug for CredentialWriterHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialWriterHandoff(<reap-only>)")
    }
}

#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "protected-channel-integration"
))]
impl ProtectedBundledRuntimeProcess {
    /// Runs the broker writer handoff for one verified macOS writer launch.
    ///
    /// The daemon acknowledges the kill exchange only after this process
    /// relinquished signal authority, so every failure here leaves the daemon
    /// holding the sole kill path and poisons this control transport.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for any stale process, frame, binding, spawn,
    /// evidence, or ownership failure.
    pub fn run_credential_writer_handoff(
        &mut self,
        writer_launch: crate::VerifiedMacOsWriterLaunch,
        mode: CredentialWriterHandoffMode,
    ) -> Result<CredentialWriterHandoff, CredentialWriterHandoffError> {
        if self.graceful_requested {
            return Err(ProtectedBundledRuntimeError::InvalidState.into());
        }
        let Some(facts) = self.enrollment_broker_facts else {
            return Err(ProtectedBundledRuntimeError::InvalidState.into());
        };
        let authenticator =
            CredentialBrokerTransferAuthenticator::from_protected_activation(&self.keys);
        let handoff = self.drive_writer_handoff(writer_launch, mode, facts, &authenticator);
        if handoff.is_err() {
            self.poison_root_transport();
        }
        handoff
    }

    fn drive_writer_handoff(
        &mut self,
        writer_launch: crate::VerifiedMacOsWriterLaunch,
        mode: CredentialWriterHandoffMode,
        facts: EnrollmentBrokerFacts,
        authenticator: &CredentialBrokerTransferAuthenticator,
    ) -> Result<CredentialWriterHandoff, CredentialWriterHandoffError> {
        let owned = match &self.activation {
            ProtectedProcessActivation::V3 { owned, .. } => owned.clone(),
            _ => return Err(ProtectedBundledRuntimeError::InvalidState.into()),
        };
        let context = ProviderCredentialBrokerHandoffContext::new(
            *owned.stable().authority_id(),
            *owned.session_id(),
            owned.launch_generation(),
            facts.binding(),
        )
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;

        broker_driver::drive(self, writer_launch, mode, facts, authenticator, &context)
    }

    /// Writes one authenticated offer and verifies the daemon's ready echo.
    fn offer_broker_transport(
        &mut self,
        context: &ProviderCredentialBrokerHandoffContext,
        authenticator: &CredentialBrokerTransferAuthenticator,
        purpose: u8,
    ) -> Result<[u8; 16], ProtectedBundledRuntimeError> {
        broker_offer::exchange(&mut self.channel, context, authenticator, purpose, || {
            crate::MacOsContinuousClock::now_millis()
                .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)
        })
    }

    /// Answers the daemon's control-channel challenge with one offered half.
    fn respond_transport_offer(
        &self,
        daemon_half: &UnixStream,
        binding: [u8; 32],
        authenticator: &CredentialBrokerTransferAuthenticator,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let mut channel = self
            .channel
            .try_clone()
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        crate::provider_credential_broker::send_daemon_control_transport_half(
            &mut channel,
            daemon_half,
            authenticator,
            binding,
        )
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
    }
}

#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "protected-channel-integration"
))]
fn unix_pair() -> Result<(UnixStream, UnixStream), ProtectedBundledRuntimeError> {
    UnixStream::pair().map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)
}
