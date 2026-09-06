#![cfg(target_os = "macos")]

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner;
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialSecretClaimOffer, CredentialSecretPublication,
    CredentialWriterSessionAttestationCodec, IssuedCredentialTicketAttempt,
};
use zeroize::Zeroizing;

use super::{CredentialBrokerChannel, pending_writer::VerifiedMacOsWriterWithDaemonKillCapability};

/// One exact writer, its kill authority, release evidence, and one-shot signer.
pub(crate) struct MacOsCredentialBrokerChannel {
    writer: VerifiedMacOsWriterWithDaemonKillCapability,
    installed: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    daemon_start: [u8; 32],
    publication: Option<CredentialSecretPublicationSigner>,
    received_frames: u8,
}

impl MacOsCredentialBrokerChannel {
    pub(crate) fn installed_measurements(
        &self,
    ) -> &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts {
        &self.installed
    }
    pub(crate) fn observe_daemon_start() -> Result<[u8; 32], runne_api::LaunchAuthorityError> {
        runne_platform_desktop::provider_credential_broker::observe_current_process_start()
            .map_err(|_| runne_api::LaunchAuthorityError::InvalidContract)
    }

    pub(crate) const fn from_verified(
        writer: VerifiedMacOsWriterWithDaemonKillCapability,
        installed: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        daemon_start: [u8; 32],
    ) -> Self {
        Self {
            writer,
            installed,
            daemon_start,
            publication: None,
            received_frames: 0,
        }
    }

    pub(crate) fn terminate_exact_writer(self) {
        let _ = self.writer.terminate_exact_writer();
    }

    pub(crate) fn send_service_handoff(
        &mut self,
        frame: runne_provider::CredentialWriterBrokerHandoffFrame,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        frame.send(|bytes| {
            std::io::Write::write_all(self.writer.control(), bytes)
                .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
        })
    }

    fn receive_once(
        &mut self,
    ) -> Result<CredentialBrokerFrame, ProviderCredentialEnrollmentHostError> {
        if self.received_frames >= 2 {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.received_frames += 1;
        CredentialBrokerFrameCodec::read_from(self.writer.control())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

impl CredentialBrokerChannel for MacOsCredentialBrokerChannel {
    fn binding_digest(&self) -> CredentialBindingDigest {
        CredentialBindingDigest::from_measured(self.writer.verified_measurement_facts().channel())
            .expect("verified channel binding")
    }

    fn send_issue(
        &mut self,
        receipt: &IssuedCredentialTicketAttempt,
        frame: CredentialBrokerFrame,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        if self.publication.is_some() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let daemon_image = self.installed.daemon();
        let (attestation, publication) =
            self.writer
                .sign_writer_session(receipt, &frame, self.daemon_start, daemon_image)?;
        let attestation = CredentialWriterSessionAttestationCodec::encode(&attestation);
        std::io::Write::write_all(self.writer.control(), &attestation)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        CredentialBrokerFrameCodec::write_to(self.writer.control(), frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        self.installed
            .write_signed_release_metadata(self.writer.control())
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        self.publication = Some(publication);
        Ok(())
    }

    fn send(
        &mut self,
        frame: Zeroizing<Vec<u8>>,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let frame = CredentialBrokerFrameCodec::decode(&frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        CredentialBrokerFrameCodec::write_to(self.writer.control(), frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
    }

    fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, ProviderCredentialEnrollmentHostError> {
        CredentialBrokerFrameCodec::encode(self.receive_once()?)
            .map(Zeroizing::new)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn sign_publication(
        &mut self,
        offer: CredentialSecretClaimOffer,
    ) -> Result<CredentialSecretPublication, ProviderCredentialEnrollmentHostError> {
        self.publication
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?
            .sign(offer, self.binding_digest())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}
