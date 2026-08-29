use std::os::unix::net::UnixStream;

use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialEnrollmentHostError,
    ProviderCredentialIntentConsumptionProof,
};
use runne_platform_desktop::provider_credential_broker::{
    ReceivedWriterProcessMeasurements, receive_daemon_owned_writer_measurements,
};
use runne_provider::CredentialOperationSnapshot;

use super::{
    pending::{AwaitingVerifiedWriter, PendingBrokerRendezvousBinding},
    rendezvous::DaemonBrokerAuthority,
};

/// Exact writer admitted to this rendezvous but not yet granted daemon kill authority.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected dispatcher consumes this before kill-capability ACK"
    )
)]
pub(crate) struct VerifiedWriterAwaitingDaemonKillCapability {
    _binding: PendingBrokerRendezvousBinding,
    _authority: DaemonBrokerAuthority,
    _measurements: ReceivedWriterProcessMeasurements,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected dispatcher receives evidence after endpoint handoff"
    )
)]
impl AwaitingVerifiedWriter {
    /// Consumes this rendezvous while receiving one authenticated evidence frame.
    pub(crate) fn receive_writer_evidence(
        self,
        transport: UnixStream,
        operation: &CredentialOperationSnapshot,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        now_high_water: i64,
    ) -> Result<VerifiedWriterAwaitingDaemonKillCapability, ProviderCredentialEnrollmentHostError>
    {
        let current =
            PendingBrokerRendezvousBinding::new(operation, authority, proof, now_high_water)?;
        if current != self.binding {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let channel = self.authority.channel_binding();
        let publication_key = self.authority.publication_public_key();
        let release_tuple = self.binding.release_tuple.as_bytes();
        let measurements = receive_daemon_owned_writer_measurements(
            transport,
            self.transfer_authority.transfer_authenticator(),
            channel,
            publication_key,
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if !measurements.matches_daemon_owned_release(release_tuple, channel, publication_key) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(VerifiedWriterAwaitingDaemonKillCapability {
            _binding: self.binding,
            _authority: self.authority,
            _measurements: measurements,
        })
    }
}

#[cfg(test)]
#[path = "pending_writer_tests.rs"]
mod tests;
