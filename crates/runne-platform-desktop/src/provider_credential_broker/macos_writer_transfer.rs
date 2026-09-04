use std::os::unix::net::UnixStream;

use runne_api::{
    CredentialBrokerTransferAuthenticator, ProviderCredentialBrokerKillRelinquishedProof,
};
use runne_macos_process_identity::MacOsPeerKillReadyProof;
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use ed25519_dalek::Signer as _;

use super::{
    VerifiedMacOsWriterProcess, daemon_evidence::send_daemon_owned_writer_evidence,
    macos_kill_exchange, unix::UnixWriterReapOnlyProcess,
};

/// Retained macOS writer after its one-shot evidence transfer began.
///
/// Dropping this pre-ACK state still terminates and reaps the exact child.
pub struct MacOsWriterTransferPending {
    writer: VerifiedMacOsWriterProcess,
}

/// Desktop's retained wait/reap half after it irrevocably relinquished signal authority.
pub struct MacOsWriterReapOnlyOwner {
    process: UnixWriterReapOnlyProcess,
}

/// Reap ownership retained even if post-relinquishment delivery was uncertain.
pub struct MacOsWriterRelinquishmentOutcome {
    owner: MacOsWriterReapOnlyOwner,
    delivery_error: Option<BrokerHandoffError>,
}

impl VerifiedMacOsWriterProcess {
    /// Revalidates and transfers evidence once over the protected daemon channel.
    ///
    /// # Errors
    ///
    /// Returns a closed failure and kills the retained child when live evidence,
    /// daemon challenge, session authentication, or rendezvous binding differs.
    pub fn transfer_evidence_to_daemon(
        mut self,
        transport: UnixStream,
        authenticator: &CredentialBrokerTransferAuthenticator,
    ) -> Result<MacOsWriterTransferPending, BrokerHandoffError> {
        self.refresh_evidence()?;
        send_daemon_owned_writer_evidence(transport, authenticator, self.evidence())?;
        Ok(MacOsWriterTransferPending { writer: self })
    }
}

impl MacOsWriterTransferPending {
    /// Completes the fixed Ready/Relinquished exchange without exposing proofs.
    ///
    /// # Errors
    ///
    /// Rejects before relinquishment when Ready is malformed or unauthenticated.
    /// After relinquishment, the returned outcome always retains reap ownership,
    /// including when proof delivery became uncertain.
    pub fn complete_daemon_kill_ownership(
        self,
        mut transport: UnixStream,
        authenticator: &CredentialBrokerTransferAuthenticator,
    ) -> Result<MacOsWriterRelinquishmentOutcome, BrokerHandoffError> {
        macos_kill_exchange::configure(&transport)?;
        let wire = macos_kill_exchange::read_one_shot::<
            { runne_macos_process_identity::MACOS_PEER_KILL_READY_WIRE_BYTES },
        >(&mut transport)?;
        let binding = self.kill_binding()?;
        let ready =
            MacOsPeerKillReadyProof::from_authenticated_wire(&wire, authenticator, &binding)
                .map_err(|_| BrokerHandoffError::Rejected)?;
        let (owner, relinquished) = self.accept_daemon_kill_ready(&ready, authenticator)?;
        let delivery_error =
            macos_kill_exchange::write_one_shot(&mut transport, &relinquished.to_exact_wire())
                .err();
        Ok(MacOsWriterRelinquishmentOutcome {
            owner,
            delivery_error,
        })
    }

    /// # Errors
    ///
    /// Rejects a ready proof not bound to this retained writer transfer.
    pub fn accept_daemon_kill_ready(
        self,
        ready: &MacOsPeerKillReadyProof,
        authenticator: &CredentialBrokerTransferAuthenticator,
    ) -> Result<
        (
            MacOsWriterReapOnlyOwner,
            ProviderCredentialBrokerKillRelinquishedProof,
        ),
        BrokerHandoffError,
    > {
        let binding = self.kill_binding()?;
        if !ready.verifies(authenticator, &binding) {
            return Err(BrokerHandoffError::Rejected);
        }
        let transcript = binding.relinquishment_transcript();
        let (process, signing_key) = self.writer.into_reap_only()?;
        let relinquished = ProviderCredentialBrokerKillRelinquishedProof::from_writer_signature(
            binding,
            signing_key.sign(&transcript).to_bytes(),
        );
        Ok((MacOsWriterReapOnlyOwner { process }, relinquished))
    }

    fn kill_binding(
        &self,
    ) -> Result<runne_api::ProviderCredentialBrokerKillBindingV1, BrokerHandoffError> {
        let (start, image, release, channel, key, writer_kill_public_key) = self
            .writer
            .evidence()
            .daemon_handoff_digests()
            .ok_or(BrokerHandoffError::Rejected)?;
        Ok(runne_api::ProviderCredentialBrokerKillBindingV1::new(
            start,
            image,
            release,
            channel,
            key,
            writer_kill_public_key,
        ))
    }
}

impl MacOsWriterRelinquishmentOutcome {
    /// Reports whether the post-transition proof reached the daemon transport.
    ///
    /// # Errors
    ///
    /// Returns the closed transport error while preserving reap ownership.
    pub const fn delivery_result(&self) -> Result<(), BrokerHandoffError> {
        match self.delivery_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    #[must_use]
    pub const fn into_reap_only_owner(self) -> MacOsWriterReapOnlyOwner {
        self.owner
    }
}

impl MacOsWriterReapOnlyOwner {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn test_child(pid: u32) -> Self {
        let pid = nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap());
        Self {
            process: super::unix::UnixRetainedWriterProcess::from_pid(pid)
                .unwrap()
                .into_reap_only(),
        }
    }

    /// # Errors
    ///
    /// Returns a closed failure if the exact retained writer cannot be reaped.
    pub fn reap_exact_writer(&mut self) -> Result<(), BrokerHandoffError> {
        self.process.reap()
    }

    pub(crate) fn reap_exact_writer_bounded(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<(), BrokerHandoffError> {
        self.process.reap_with_timeout(timeout)
    }
}

impl std::fmt::Debug for MacOsWriterTransferPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacOsWriterTransferPending(<retained-pre-ack>)")
    }
}
impl std::fmt::Debug for MacOsWriterReapOnlyOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MacOsWriterReapOnlyOwner(<wait-reap-only>)")
    }
}
impl std::fmt::Debug for MacOsWriterRelinquishmentOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOsWriterRelinquishmentOutcome")
            .field("delivery_succeeded", &self.delivery_error.is_none())
            .finish_non_exhaustive()
    }
}
