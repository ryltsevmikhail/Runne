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

/// Desktop-held state after the daemon acknowledged the kill exchange.
#[cfg(target_os = "macos")]
pub struct CredentialWriterHandoff {
    owner: crate::provider_credential_broker::MacOsWriterReapOnlyOwner,
}

#[cfg(target_os = "macos")]
impl CredentialWriterHandoff {
    /// Reaps the exact writer after the daemon owns its kill authority.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the retained writer cannot be reaped.
    pub fn reap_exact_writer(self) -> Result<(), ProtectedBundledRuntimeError> {
        self.owner
            .reap_exact_writer()
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
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
    ) -> Result<CredentialWriterHandoff, ProtectedBundledRuntimeError> {
        if self.graceful_requested {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let Some(facts) = self.enrollment_broker_facts else {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        };
        let authenticator =
            CredentialBrokerTransferAuthenticator::from_protected_activation(&self.keys);
        let handoff = self.drive_writer_handoff(writer_launch, facts, &authenticator);
        if handoff.is_err() {
            self.poison_root_transport();
        }
        handoff
    }

    fn drive_writer_handoff(
        &mut self,
        writer_launch: crate::VerifiedMacOsWriterLaunch,
        facts: EnrollmentBrokerFacts,
        authenticator: &CredentialBrokerTransferAuthenticator,
    ) -> Result<CredentialWriterHandoff, ProtectedBundledRuntimeError> {
        let owned = match &self.activation {
            ProtectedProcessActivation::V3 { owned, .. } => owned.clone(),
            _ => return Err(ProtectedBundledRuntimeError::InvalidState),
        };
        let context = ProviderCredentialBrokerHandoffContext::new(
            *owned.stable().authority_id(),
            *owned.session_id(),
            owned.launch_generation(),
            facts.binding(),
        )
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;

        // Purpose 1: offer the daemon half of the endpoint transport, answer
        // the challenge, and spawn the fixed writer with the desktop half.
        self.offer_broker_transport(
            &context,
            authenticator,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        )?;
        let (endpoint_half, endpoint_daemon_half) = unix_pair()?;
        self.respond_transport_offer(&endpoint_daemon_half, facts.binding(), authenticator)?;
        let prepared =
            crate::provider_credential_broker::prepare_daemon_owned_writer_endpoint_handoff(
                endpoint_half,
                authenticator,
                facts.binding(),
                facts.publication_public_key(),
            )
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let writer =
            crate::provider_credential_broker::spawn_macos_verified_writer_from_prepared_daemon_handoff(
                writer_launch,
                prepared,
            )
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;

        // Purpose 2: offer the evidence transport and answer its challenge.
        self.offer_broker_transport(
            &context,
            authenticator,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_EVIDENCE,
        )?;
        let (evidence_half, evidence_daemon_half) = unix_pair()?;
        self.respond_transport_offer(&evidence_daemon_half, facts.binding(), authenticator)?;
        let pending = writer
            .transfer_evidence_to_daemon(evidence_half, authenticator)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;

        // Purpose 3: offer the kill transport and complete the fixed
        // Ready/Relinquished exchange before the daemon's acknowledgement.
        let nonce = self.offer_broker_transport(
            &context,
            authenticator,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
        )?;
        let (kill_half, kill_daemon_half) = unix_pair()?;
        self.respond_transport_offer(&kill_daemon_half, facts.binding(), authenticator)?;
        let outcome = pending
            .complete_daemon_kill_ownership(kill_half, authenticator)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        // A delivered acknowledgement proves the daemon read the relinquished
        // wire; a failed delivery with an acknowledgement is contradictory.
        if outcome.delivery_result().is_err() {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }

        let now = crate::MacOsContinuousClock::now_millis()
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        let frame = read_frame(&mut self.channel)?;
        ProviderCredentialBrokerHandoffFrame::decode_and_verify(
            &frame,
            authenticator,
            &context,
            ProviderCredentialBrokerHandoffFrame::PHASE_ACK,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
            nonce,
            now,
        )
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        Ok(CredentialWriterHandoff {
            owner: outcome.into_reap_only_owner(),
        })
    }

    /// Writes one authenticated offer and verifies the daemon's ready echo.
    fn offer_broker_transport(
        &mut self,
        context: &ProviderCredentialBrokerHandoffContext,
        authenticator: &CredentialBrokerTransferAuthenticator,
        purpose: u8,
    ) -> Result<[u8; 16], ProtectedBundledRuntimeError> {
        let now = crate::MacOsContinuousClock::now_millis()
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        let expires = now
            .checked_add(30_000)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let mut nonce = [0; 16];
        rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut nonce)
            .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
        let offer = ProviderCredentialBrokerHandoffFrame::offer(
            context.clone(),
            purpose,
            now,
            expires,
            nonce,
            authenticator,
        )
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        write_frame(&mut self.channel, &offer.encode_frame())?;
        let frame = read_frame(&mut self.channel)?;
        ProviderCredentialBrokerHandoffFrame::decode_and_verify(
            &frame,
            authenticator,
            context,
            ProviderCredentialBrokerHandoffFrame::PHASE_READY,
            purpose,
            nonce,
            now,
        )
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        Ok(nonce)
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
