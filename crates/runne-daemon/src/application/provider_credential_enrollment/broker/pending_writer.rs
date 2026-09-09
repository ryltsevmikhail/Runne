#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
use std::os::unix::net::UnixStream;

#[cfg(test)]
use runne_api::{ProviderCredentialBaseRequestAuthority, ProviderCredentialIntentConsumptionProof};
use runne_api::{ProviderCredentialBrokerTransferAuthority, ProviderCredentialEnrollmentHostError};
#[cfg(target_os = "macos")]
use runne_platform_desktop::provider_credential_broker::{
    MacOsPeerKillCapability, MacOsPeerKillPending, capture_macos_daemon_peer_kill_capability,
};
use runne_platform_desktop::provider_credential_broker::{
    ReceivedWriterProcessMeasurements, receive_daemon_owned_writer_measurements,
};
#[cfg(target_os = "macos")]
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
#[cfg(test)]
use runne_provider::CredentialOperationSnapshot;

use super::{
    pending::{AwaitingVerifiedWriter, PendingBrokerRendezvousBinding},
    rendezvous::DaemonBrokerAuthority,
};

#[cfg(target_os = "macos")]
#[path = "pending_writer/qualified.rs"]
mod qualified;

/// Exact writer admitted to this rendezvous but not yet granted daemon kill authority.
pub(crate) struct VerifiedWriterAwaitingDaemonKillCapability {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    transfer_authority: ProviderCredentialBrokerTransferAuthority,
    measurements: ReceivedWriterProcessMeasurements,
    handoff: runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

/// Exact macOS writer captured by daemon but not kill-enabled before Desktop relinquishes.
#[cfg(target_os = "macos")]
pub(crate) struct VerifiedMacOsWriterKillReady {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    transfer_authority: ProviderCredentialBrokerTransferAuthority,
    kill: MacOsPeerKillPending,
    handoff: runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

/// Exact macOS writer whose daemon-owned endpoint yielded a matching kernel token.
#[cfg(target_os = "macos")]
pub(crate) struct VerifiedMacOsWriterWithDaemonKillCapability {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    kill: MacOsPeerKillCapability,
    handoff: runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

impl AwaitingVerifiedWriter {
    pub(crate) const fn transfer_authority(&self) -> &ProviderCredentialBrokerTransferAuthority {
        &self.transfer_authority
    }

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

impl VerifiedWriterAwaitingDaemonKillCapability {
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
impl VerifiedMacOsWriterWithDaemonKillCapability {
    pub(crate) const fn verified_measurement_facts(
        &self,
    ) -> &runne_platform_desktop::provider_credential_broker::VerifiedWriterMeasurementFacts {
        self.kill.verified_measurement_facts()
    }

    pub(in crate::application::provider_credential_enrollment::broker) fn control(
        &mut self,
    ) -> &mut UnixStream {
        self.authority.endpoint_mut()
    }

    pub(in crate::application::provider_credential_enrollment::broker) fn sign_writer_session(
        &mut self,
        receipt: &runne_provider::IssuedCredentialTicketAttempt,
        frame: &runne_provider::CredentialBrokerFrame,
        daemon_start: [u8; 32],
        daemon_image: [u8; 32],
    ) -> Result<
        (
            runne_provider::SignedCredentialWriterSessionAttestationV1,
            runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let issue = runne_provider::CredentialIssueTicketBindingV1::from_issue_ticket(frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let runne_provider::CredentialBrokerFrame::IssueTicket { binding, .. } = frame else {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        };
        let digest = |value| {
            runne_provider::CredentialBindingDigest::from_measured(value)
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
        };
        let writer = self.verified_measurement_facts();
        let claims = runne_provider::CredentialWriterSessionAttestationClaimsV1::new(
            runne_provider::CredentialWriterSessionTicketClaimsV1::new(
                receipt.operation().operation_id(),
                receipt.ticket_attempt(),
                issue,
                *binding,
                self.binding.owner,
                self.binding.begin_proof,
                receipt.issued_at_high_water(),
                receipt.expires_at_high_water(),
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
            runne_provider::CredentialWriterSessionRuntimeClaimsV1::new(
                digest(self.binding.protected_session)?,
                digest(self.binding.tauri_peer)?,
                digest(self.binding.daemon_authority)?,
                self.binding.database_generation,
                self.binding.supervisor_generation,
                self.binding.release_tuple,
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
            runne_provider::CredentialWriterSessionProcessClaimsV1::new(
                digest(self.handoff.digest())?,
                digest(writer.process_start())?,
                digest(writer.image())?,
                digest(writer.writer_kill_public_key())?,
                digest(daemon_start)?,
                digest(daemon_image)?,
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
        );
        self.authority.sign_writer_session(claims)
    }

    pub(crate) fn matches_bound_operation(
        &self,
        operation_id: runne_provider::CredentialOperationId,
        channel: [u8; 32],
        publication_public_key: [u8; 32],
    ) -> bool {
        self.binding.operation_id == operation_id
            && self.authority.channel_binding() == channel
            && self.authority.publication_public_key() == publication_public_key
            && self.kill.verified_measurement_facts().channel() == channel
            && self
                .kill
                .verified_measurement_facts()
                .publication_public_key()
                == publication_public_key
    }

    pub(crate) fn terminate_exact_writer(
        self,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.kill.terminate_exact_peer().map_err(map_handoff)
    }
}

#[cfg(target_os = "macos")]
const fn map_handoff(error: BrokerHandoffError) -> ProviderCredentialEnrollmentHostError {
    match error {
        BrokerHandoffError::Rejected => ProviderCredentialEnrollmentHostError::AccessDenied,
        BrokerHandoffError::Unavailable => ProviderCredentialEnrollmentHostError::Unavailable,
    }
}

#[cfg(test)]
#[path = "pending_writer_tests.rs"]
mod tests;
