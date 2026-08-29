use std::os::unix::net::UnixStream;

#[cfg(target_os = "macos")]
use runne_api::ProviderCredentialBrokerKillRelinquishedProof;
use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialBrokerTransferAuthority,
    ProviderCredentialEnrollmentHostError, ProviderCredentialIntentConsumptionProof,
};
#[cfg(target_os = "macos")]
use runne_platform_desktop::provider_credential_broker::{
    MacOsPeerKillCapability, MacOsPeerKillPending, MacOsPeerKillReadyProof,
    capture_macos_daemon_peer_kill_capability,
};
use runne_platform_desktop::provider_credential_broker::{
    ReceivedWriterProcessMeasurements, receive_daemon_owned_writer_measurements,
};
#[cfg(target_os = "macos")]
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
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
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    transfer_authority: ProviderCredentialBrokerTransferAuthority,
    measurements: ReceivedWriterProcessMeasurements,
}

/// Exact macOS writer captured by daemon but not kill-enabled before Desktop relinquishes.
#[cfg(target_os = "macos")]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "awaits authenticated Desktop relinquishment")
)]
pub(crate) struct VerifiedMacOsWriterKillReady {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    transfer_authority: ProviderCredentialBrokerTransferAuthority,
    kill: MacOsPeerKillPending,
}

/// Exact macOS writer whose daemon-owned endpoint yielded a matching kernel token.
#[cfg(target_os = "macos")]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected dispatcher retains this after kill-capability ACK"
    )
)]
pub(crate) struct VerifiedMacOsWriterWithDaemonKillCapability {
    _binding: PendingBrokerRendezvousBinding,
    _authority: DaemonBrokerAuthority,
    kill: MacOsPeerKillCapability,
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
        let (measurements, transfer_authority) = receive_daemon_owned_writer_measurements(
            transport,
            self.transfer_authority,
            release_tuple,
            channel,
            publication_key,
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if !measurements.matches_daemon_owned_release(release_tuple, channel, publication_key) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(VerifiedWriterAwaitingDaemonKillCapability {
            binding: self.binding,
            authority: self.authority,
            transfer_authority,
            measurements,
        })
    }
}

#[cfg(target_os = "macos")]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected dispatcher captures this before sending ACK"
    )
)]
impl VerifiedWriterAwaitingDaemonKillCapability {
    /// Captures the exact kernel peer authority before Desktop may accept ACK.
    pub(crate) fn capture_macos_kill_capability(
        self,
    ) -> Result<VerifiedMacOsWriterKillReady, ProviderCredentialEnrollmentHostError> {
        let kill = capture_macos_daemon_peer_kill_capability(
            self.authority.endpoint(),
            self.measurements,
            &self.transfer_authority,
        )
        .map_err(map_handoff)?;
        Ok(VerifiedMacOsWriterKillReady {
            binding: self.binding,
            authority: self.authority,
            transfer_authority: self.transfer_authority,
            kill,
        })
    }
}

#[cfg(target_os = "macos")]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected dispatcher completes authenticated kill ownership transfer"
    )
)]
impl VerifiedMacOsWriterKillReady {
    pub(crate) fn ready_proof(
        &self,
    ) -> Result<MacOsPeerKillReadyProof, ProviderCredentialEnrollmentHostError> {
        self.kill
            .issue_ready(&self.transfer_authority)
            .map_err(map_handoff)
    }

    pub(crate) fn enable_after_relinquished(
        self,
        proof: &ProviderCredentialBrokerKillRelinquishedProof,
    ) -> Result<VerifiedMacOsWriterWithDaemonKillCapability, ProviderCredentialEnrollmentHostError>
    {
        let kill = self
            .kill
            .enable_after_relinquished(&self.transfer_authority, proof)
            .map_err(map_handoff)?;
        Ok(VerifiedMacOsWriterWithDaemonKillCapability {
            _binding: self.binding,
            _authority: self.authority,
            kill,
        })
    }
}

#[cfg(target_os = "macos")]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "timeout recovery consumes exact kill ownership")
)]
impl VerifiedMacOsWriterWithDaemonKillCapability {
    pub(crate) fn terminate_exact_writer(
        self,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.kill.terminate_exact_peer().map_err(map_handoff)
    }
}

#[cfg(target_os = "macos")]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the pending protected dispatcher path")
)]
const fn map_handoff(error: BrokerHandoffError) -> ProviderCredentialEnrollmentHostError {
    match error {
        BrokerHandoffError::Rejected => ProviderCredentialEnrollmentHostError::AccessDenied,
        BrokerHandoffError::Unavailable => ProviderCredentialEnrollmentHostError::Unavailable,
    }
}

#[cfg(test)]
#[path = "pending_writer_tests.rs"]
mod tests;
