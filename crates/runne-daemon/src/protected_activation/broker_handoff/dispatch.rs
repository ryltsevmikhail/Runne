#![expect(
    dead_code,
    reason = "the V3 launch loop that drives the handoff purposes lands with a later composition slice"
)]

use std::os::unix::net::UnixStream;

#[cfg(target_os = "macos")]
use runne_platform_desktop::provider_credential_broker::capture_macos_daemon_peer_kill_capability;
use runne_platform_desktop::provider_credential_broker::{
    receive_daemon_control_transport_half, receive_daemon_owned_writer_measurements,
    send_daemon_owned_writer_endpoint,
};

use super::*;

impl BrokerHandoffDispatch {
    pub(super) fn run_purpose(
        &mut self,
        purpose: u8,
        channel: &mut ProtectedActivationChannel,
    ) -> Result<(), LaunchAuthorityError> {
        match purpose {
            ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT => self.run_endpoint(channel),
            ProviderCredentialBrokerHandoffFrame::PURPOSE_EVIDENCE => self.run_evidence(channel),
            ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL => self.run_kill_purpose(channel),
            _ => Err(LaunchAuthorityError::InvalidContract),
        }
    }

    fn run_endpoint(
        &mut self,
        channel: &mut ProtectedActivationChannel,
    ) -> Result<(), LaunchAuthorityError> {
        let half = self.receive_half(channel)?;
        if let Some(endpoint) = self.bound_endpoint.take() {
            let authority = self
                .authority
                .take()
                .ok_or(LaunchAuthorityError::InvalidContract)?;
            self.bound_writer = Some(
                endpoint
                    .send_endpoint(half, authority)
                    .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?,
            );
            return Ok(());
        }
        let writer = self
            .rendezvous
            .as_mut()
            .ok_or(LaunchAuthorityError::InvalidContract)?
            .take_writer_endpoint()
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        send_daemon_owned_writer_endpoint(
            half,
            writer,
            self.author()?,
            self.binding,
            self.publication_public_key,
        )
        .map(|_| ())
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
    }

    fn run_evidence(
        &mut self,
        channel: &mut ProtectedActivationChannel,
    ) -> Result<(), LaunchAuthorityError> {
        let half = self.receive_half(channel)?;
        if let Some(writer) = self.bound_writer.take() {
            self.verified_writer = Some(
                writer
                    .receive_bound_writer_evidence(half)
                    .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?,
            );
            return Ok(());
        }
        let authority = self
            .authority
            .take()
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        let (measurements, authority) = receive_daemon_owned_writer_measurements(
            half,
            authority,
            self.release_tuple,
            self.binding,
            self.publication_public_key,
        )
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
        if !measurements.matches_daemon_owned_release(
            self.release_tuple,
            self.binding,
            self.publication_public_key,
        ) {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        self.authority = Some(authority);
        self.measurements = Some(measurements);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn run_kill_purpose(
        &mut self,
        channel: &mut ProtectedActivationChannel,
    ) -> Result<(), LaunchAuthorityError> {
        let half = self.receive_half(channel)?;
        if let Some(writer) = self.verified_writer.take() {
            let retained = writer
                .capture_macos_kill_capability()
                .and_then(|ready| ready.complete_ownership_exchange(half))
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
            if !retained.matches_bound_operation(
                self.expected_operation
                    .ok_or(LaunchAuthorityError::InvalidContract)?,
                self.binding,
                self.publication_public_key,
            ) {
                return Err(LaunchAuthorityError::OwnershipMismatch);
            }
            self.bound_kill = Some(retained);
            return self.write_kill_ack(channel);
        }
        let measurements = self
            .measurements
            .take()
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        let pending = capture_macos_daemon_peer_kill_capability(
            self.rendezvous
                .as_ref()
                .ok_or(LaunchAuthorityError::InvalidContract)?
                .broker_authority()
                .endpoint(),
            measurements,
            self.author()?,
        )
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
        self.kill = Some(
            pending
                .complete_desktop_relinquishment(half, self.author()?)
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?,
        );
        self.write_kill_ack(channel)
    }

    #[cfg(not(target_os = "macos"))]
    fn run_kill_purpose(
        &mut self,
        _channel: &mut ProtectedActivationChannel,
    ) -> Result<(), LaunchAuthorityError> {
        Err(LaunchAuthorityError::UnsupportedPlatformBackend)
    }

    #[cfg(target_os = "macos")]
    fn write_kill_ack(
        &mut self,
        channel: &mut ProtectedActivationChannel,
    ) -> Result<(), LaunchAuthorityError> {
        let acknowledgement = self
            .offer
            .take()
            .ok_or(LaunchAuthorityError::InvalidContract)?
            .acknowledgement(&self.authenticator);
        channel.write_control_frame(&acknowledgement.encode_frame())
    }

    fn author(&self) -> Result<&ProviderCredentialBrokerTransferAuthority, LaunchAuthorityError> {
        self.authority
            .as_ref()
            .or_else(|| {
                self.bound_writer
                    .as_ref()
                    .map(AwaitingVerifiedWriter::transfer_authority)
            })
            .or_else(|| {
                self.verified_writer
                    .as_ref()
                    .map(VerifiedWriterAwaitingDaemonKillCapability::transfer_authority)
            })
            .ok_or(LaunchAuthorityError::InvalidContract)
    }

    fn receive_half(
        &self,
        channel: &mut ProtectedActivationChannel,
    ) -> Result<UnixStream, LaunchAuthorityError> {
        let mut stream = channel
            .unix_stream()
            .try_clone()
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        receive_daemon_control_transport_half(&mut stream, self.author()?, self.binding)
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
    }
}
