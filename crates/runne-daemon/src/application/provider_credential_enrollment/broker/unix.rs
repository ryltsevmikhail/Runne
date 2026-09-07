#![cfg(target_os = "macos")]

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner;
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialSecretClaimOffer, CredentialSecretPublication, CredentialWriterQualifiedAckCodec,
    CredentialWriterQualifiedAckSigner, CredentialWriterQualifiedPreludeSigner,
    CredentialWriterSessionAttestationCodec, CredentialWriterSessionAttestationV2Codec,
    IssuedCredentialTicketAttempt,
};
use zeroize::Zeroizing;

use super::qualified_exchange::QualifiedCredentialBrokerChannel;
use super::{
    CredentialBrokerChannel, QualifiedIssueTransmission,
    pending_writer::VerifiedMacOsWriterWithDaemonKillCapability,
};

mod qualified;
use self::qualified::{BUDGET as QUALIFIED_EXCHANGE_BUDGET, QualifiedControl};

enum QualifiedSignerState {
    Prelude {
        signer: CredentialWriterQualifiedPreludeSigner,
        bundle: Vec<u8>,
    },
    Ack(CredentialWriterQualifiedAckSigner),
}

/// One exact writer, its kill authority, release evidence, and one-shot signer.
pub(crate) struct MacOsCredentialBrokerChannel {
    writer: VerifiedMacOsWriterWithDaemonKillCapability,
    installed: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    daemon_start: [u8; 32],
    publication: Option<CredentialSecretPublicationSigner>,
    qualified: Option<QualifiedSignerState>,
    qualified_deadline: Option<std::time::Instant>,
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
            qualified: None,
            qualified_deadline: None,
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
        if let Some(deadline) = self.qualified_deadline {
            let mut control = QualifiedControl::new(self.writer.control(), deadline);
            CredentialBrokerFrameCodec::read_from(&mut control)
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
        } else {
            CredentialBrokerFrameCodec::read_from(self.writer.control())
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
        }
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
        if self.publication.is_some() || self.qualified.is_some() {
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
        if let Some(deadline) = self.qualified_deadline {
            let mut control = QualifiedControl::new(self.writer.control(), deadline);
            CredentialBrokerFrameCodec::write_to(&mut control, frame)
                .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
            self.qualified_deadline = None;
            Ok(())
        } else {
            CredentialBrokerFrameCodec::write_to(self.writer.control(), frame)
                .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
        }
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

impl QualifiedCredentialBrokerChannel for MacOsCredentialBrokerChannel {
    fn send_qualified_issue(
        &mut self,
        issue: QualifiedIssueTransmission,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        if self.publication.is_some() || self.qualified.is_some() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let (receipt, frame, launch_generation, admission) = issue.into_signing_parts();
        let (context_sha256, ticket_sha256, bundle) = admission.into_qualified_signing_material();
        let (attestation, signer) = self.writer.sign_writer_session_qualified(
            &receipt,
            &frame,
            self.daemon_start,
            self.installed.daemon(),
            launch_generation,
            context_sha256,
            ticket_sha256,
        )?;
        std::io::Write::write_all(
            self.writer.control(),
            &CredentialWriterSessionAttestationV2Codec::encode(&attestation),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        CredentialBrokerFrameCodec::write_to(self.writer.control(), frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        self.installed
            .write_signed_release_metadata(self.writer.control())
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        self.qualified = Some(QualifiedSignerState::Prelude { signer, bundle });
        self.qualified_deadline = Some(
            std::time::Instant::now()
                .checked_add(QUALIFIED_EXCHANGE_BUDGET)
                .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?,
        );
        Ok(())
    }

    fn send_qualified_prelude(&mut self) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let Some(QualifiedSignerState::Prelude { signer, bundle }) = self.qualified.take() else {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        };
        let deadline = self
            .qualified_deadline
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let (prelude, signer) = signer
            .sign_prelude(bundle)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let bytes = runne_provider::CredentialWriterQualifiedPreludeCodec::encode(&prelude)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let mut control = QualifiedControl::new(self.writer.control(), deadline);
        std::io::Write::write_all(&mut control, &bytes)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        self.qualified = Some(QualifiedSignerState::Ack(signer));
        Ok(())
    }

    fn receive_qualified_ack(&mut self) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let Some(QualifiedSignerState::Ack(signer)) = self.qualified.take() else {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        };
        let deadline = self
            .qualified_deadline
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let mut bytes = [0; CredentialWriterQualifiedAckCodec::BYTES];
        let mut control = QualifiedControl::new(self.writer.control(), deadline);
        std::io::Read::read_exact(&mut control, &mut bytes)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let ack = CredentialWriterQualifiedAckCodec::decode(&bytes)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let publication = signer
            .accept_ack(ack)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        control
            .ensure_remaining()
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.publication = Some(publication);
        Ok(())
    }

    fn qualified_exchange_check(&mut self) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let deadline = self
            .qualified_deadline
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        QualifiedControl::check_deadline(deadline)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}
