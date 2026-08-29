use std::os::unix::net::UnixStream;

use runne_api::CredentialBrokerTransferAuthenticator;
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::{VerifiedMacOsWriterProcess, daemon_evidence::send_daemon_owned_writer_evidence};

/// Retained macOS writer after its one-shot evidence transfer began.
///
/// Dropping this pre-ACK state still terminates and reaps the exact child.
pub struct MacOsWriterTransferPending {
    _writer: VerifiedMacOsWriterProcess,
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
        Ok(MacOsWriterTransferPending { _writer: self })
    }
}

impl std::fmt::Debug for MacOsWriterTransferPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacOsWriterTransferPending(<retained-pre-ack>)")
    }
}
