use std::os::unix::net::UnixStream;

use runne_api::{
    CredentialBrokerTransferAuthenticator, ProviderCredentialBrokerKillRelinquishedProof,
};
use runne_macos_process_identity::MacOsPeerKillReadyProof;
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use ed25519_dalek::Signer as _;

use super::{
    VerifiedMacOsWriterProcess, daemon_evidence::send_daemon_owned_writer_evidence,
    unix::UnixWriterReapOnlyProcess,
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
        let (start, image, release, channel, key, writer_kill_public_key) = self
            .writer
            .evidence()
            .daemon_handoff_digests()
            .ok_or(BrokerHandoffError::Rejected)?;
        let binding = runne_api::ProviderCredentialBrokerKillBindingV1::new(
            start,
            image,
            release,
            channel,
            key,
            writer_kill_public_key,
        );
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
}

impl MacOsWriterReapOnlyOwner {
    /// # Errors
    ///
    /// Returns a closed failure if the exact retained writer cannot be reaped.
    pub fn reap_exact_writer(self) -> Result<(), BrokerHandoffError> {
        self.process.reap()
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
