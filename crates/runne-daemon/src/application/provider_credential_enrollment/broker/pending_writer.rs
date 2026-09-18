#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use std::os::unix::net::UnixStream;

#[cfg(test)]
use runne_api::{ProviderCredentialBaseRequestAuthority, ProviderCredentialIntentConsumptionProof};
#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_api::{ProviderCredentialBrokerTransferAuthority, ProviderCredentialEnrollmentHostError};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use runne_platform_desktop::provider_credential_broker::{
    MacOsPeerKillCapability, MacOsPeerKillPending, capture_macos_daemon_peer_kill_capability,
};
#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_platform_desktop::provider_credential_broker::{
    ReceivedWriterProcessMeasurements, receive_daemon_owned_writer_measurements,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
#[cfg(test)]
use runne_provider::CredentialOperationSnapshot;

#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use super::{
    pending::{AwaitingVerifiedWriter, PendingBrokerRendezvousBinding},
    rendezvous::DaemonBrokerAuthority,
};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "pending_writer/native_writer.rs"]
mod native_writer;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "pending_writer/qualified.rs"]
mod qualified;

/// Exact writer admitted to this rendezvous but not yet granted daemon kill authority.
#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    expect(
        dead_code,
        reason = "portable evidence tests retain native kill-admission members"
    )
)]
#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(crate) struct VerifiedWriterAwaitingDaemonKillCapability {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    transfer_authority: ProviderCredentialBrokerTransferAuthority,
    measurements: ReceivedWriterProcessMeasurements,
    handoff: runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

/// Exact macOS writer captured by daemon but not kill-enabled before Desktop relinquishes.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct VerifiedMacOsWriterKillReady {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    transfer_authority: ProviderCredentialBrokerTransferAuthority,
    kill: MacOsPeerKillPending,
    handoff: runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

/// Exact macOS writer whose daemon-owned endpoint yielded a matching kernel token.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct VerifiedMacOsWriterWithDaemonKillCapability {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    kill: MacOsPeerKillCapability,
    handoff: runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
impl AwaitingVerifiedWriter {
    /// Broker-API surface; consumed by the macOS credential-writer handoff.
    #[allow(dead_code)]
    pub(crate) const fn transfer_authority(&self) -> &ProviderCredentialBrokerTransferAuthority {
        &self.transfer_authority
    }

    /// Broker-API surface; consumed by the macOS credential-writer handoff.
    #[allow(dead_code)]
    pub(crate) fn receive_bound_writer_evidence(
        self,
        transport: UnixStream,
    ) -> Result<VerifiedWriterAwaitingDaemonKillCapability, ProviderCredentialEnrollmentHostError>
    {
        self.receive_verified_evidence(transport)
    }

    /// Consumes this rendezvous while receiving one authenticated evidence frame.
    #[cfg(test)]
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
        self.receive_verified_evidence(transport)
    }

    fn receive_verified_evidence(
        self,
        transport: UnixStream,
    ) -> Result<VerifiedWriterAwaitingDaemonKillCapability, ProviderCredentialEnrollmentHostError>
    {
        let channel = self.authority.channel_binding();
        let publication_key = self.authority.publication_public_key();
        let release_tuple = self.binding.release_tuple();
        let release_tuple = release_tuple.as_bytes();
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
            handoff: self.handoff,
        })
    }
}

#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
impl VerifiedWriterAwaitingDaemonKillCapability {
    /// Broker-API surface; consumed by the macOS credential-writer handoff.
    #[allow(dead_code)]
    pub(crate) const fn transfer_authority(&self) -> &ProviderCredentialBrokerTransferAuthority {
        &self.transfer_authority
    }

    /// Captures the exact kernel peer authority before Desktop may accept ACK.
    #[cfg(target_os = "macos")]
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
            handoff: self.handoff,
        })
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl VerifiedMacOsWriterKillReady {
    pub(crate) fn complete_ownership_exchange(
        self,
        transport: UnixStream,
    ) -> Result<VerifiedMacOsWriterWithDaemonKillCapability, ProviderCredentialEnrollmentHostError>
    {
        let kill = self
            .kill
            .complete_desktop_relinquishment(transport, &self.transfer_authority)
            .map_err(map_handoff)?;
        Ok(VerifiedMacOsWriterWithDaemonKillCapability {
            binding: self.binding,
            authority: self.authority,
            kill,
            handoff: self.handoff,
        })
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const fn map_handoff(error: BrokerHandoffError) -> ProviderCredentialEnrollmentHostError {
    match error {
        BrokerHandoffError::Rejected => ProviderCredentialEnrollmentHostError::AccessDenied,
        BrokerHandoffError::Unavailable => ProviderCredentialEnrollmentHostError::Unavailable,
    }
}

#[cfg(test)]
#[path = "pending_writer_tests.rs"]
mod tests;
