//! Linux credential broker channel over the pidfd-owned writer authority
//! (M6 step 1 consumer). Mirrors the macOS channel contract — same frames,
//! same attestation/publication signing flow, same one-shot receive budget
//! and the same `QualifiedControl` deadline discipline — with Linux fact
//! sources: measured admission facts instead of the macOS signed-release
//! metadata write, and pidfd kill/reap for termination.

#![expect(
    dead_code,
    reason = "the D1 Linux composition slice mounts the broker channel; tests drive it today"
)]

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner;
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialSecretClaimOffer, CredentialSecretPublication, CredentialWriterQualifiedAckCodec,
    CredentialWriterQualifiedPreludeSigner, IssuedCredentialTicketAttempt,
};
use zeroize::Zeroizing;

use super::pending::PendingBrokerRendezvousBinding;
use super::pending_writer::{
    QualifiedWriterSessionMaterial, VerifiedLinuxWriterWithDaemonAuthority, WriterProcessFacts,
};
use super::qualified_control::{BUDGET as QUALIFIED_EXCHANGE_BUDGET, QualifiedControl};
use super::{
    CredentialBrokerChannel, QualifiedCredentialBrokerChannel, QualifiedIssueTransmission,
};

pub(crate) struct LinuxCredentialBrokerChannel {
    writer: VerifiedLinuxWriterWithDaemonAuthority,
    daemon_start: [u8; 32],
    daemon_image: [u8; 32],
    publication: Option<CredentialSecretPublicationSigner>,
    qualified: Option<QualifiedState>,
    qualified_deadline: Option<std::time::Instant>,
    received_frames: u8,
}

enum QualifiedState {
    Prelude {
        signer: CredentialWriterQualifiedPreludeSigner,
        bundle: Vec<u8>,
    },
    Ack(runne_provider::CredentialWriterQualifiedAckSigner),
}

impl LinuxCredentialBrokerChannel {
    pub(crate) fn installed_daemon_image(
        &self,
    ) -> Result<[u8; 32], ProviderCredentialEnrollmentHostError> {
        Ok(self.daemon_image)
    }

    pub(crate) fn observe_daemon_start() -> Result<[u8; 32], runne_api::LaunchAuthorityError> {
        runne_platform_desktop::provider_credential_broker::observe_current_process_start()
            .map_err(|_| runne_api::LaunchAuthorityError::InvalidContract)
    }

    pub(crate) fn from_admitted(
        writer: VerifiedLinuxWriterWithDaemonAuthority,
        daemon_start: [u8; 32],
        daemon_image: [u8; 32],
    ) -> Self {
        Self {
            writer,
            daemon_start,
            daemon_image,
            publication: None,
            qualified: None,
            qualified_deadline: None,
            received_frames: 0,
        }
    }

    pub(crate) fn claim_process_facts(
        &self,
    ) -> Result<WriterProcessFacts, ProviderCredentialEnrollmentHostError> {
        self.writer.claim_process_facts()
    }

    /// The rendezvous binding this exact writer was admitted against.
    #[expect(
        dead_code,
        reason = "reserved for the D1 composition slice's channel binding check"
    )]
    pub(in crate::application::provider_credential_enrollment::broker) fn binding(
        &self,
    ) -> &PendingBrokerRendezvousBinding {
        self.writer.binding()
    }

    pub(crate) fn terminate_exact_writer(self) {
        let _ = self.writer.terminate_exact_writer();
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

impl CredentialBrokerChannel for LinuxCredentialBrokerChannel {
    fn binding_digest(&self) -> CredentialBindingDigest {
        CredentialBindingDigest::from_measured(self.writer.channel_binding())
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
        let (attestation, publication) = self.writer.sign_writer_session(
            receipt,
            &frame,
            self.daemon_start,
            self.daemon_image,
        )?;
        let attestation =
            runne_provider::CredentialWriterSessionAttestationCodec::encode(&attestation);
        std::io::Write::write_all(self.writer.control(), &attestation)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        CredentialBrokerFrameCodec::write_to(self.writer.control(), frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        // Linux release pin is the approved local content binding carried in
        // the attestation claims; there is no macOS signed-release metadata
        // document to forward here.
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

impl QualifiedCredentialBrokerChannel for LinuxCredentialBrokerChannel {
    fn send_qualified_issue(
        &mut self,
        issue: QualifiedIssueTransmission,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        if self.publication.is_some() || self.qualified.is_some() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let (receipt, frame, launch_generation, admission) = issue.into_signing_parts();
        let (context_sha256, ticket_sha256, bundle) = admission.into_qualified_signing_material();
        let material = QualifiedWriterSessionMaterial {
            daemon_start: self.daemon_start,
            daemon_image: self.daemon_image,
            launch_generation,
            context_sha256,
            ticket_sha256,
        };
        let (attestation, signer) = self
            .writer
            .sign_writer_session_qualified(&receipt, &frame, &material)?;
        std::io::Write::write_all(
            self.writer.control(),
            &runne_provider::CredentialWriterSessionAttestationV2Codec::encode(&attestation),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        CredentialBrokerFrameCodec::write_to(self.writer.control(), frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        // Same position as the macOS channel minus the signed-release
        // metadata write: the Linux release pin rides the attestation claims.
        self.qualified = Some(QualifiedState::Prelude { signer, bundle });
        self.qualified_deadline = Some(
            std::time::Instant::now()
                .checked_add(QUALIFIED_EXCHANGE_BUDGET)
                .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?,
        );
        Ok(())
    }

    fn send_qualified_prelude(&mut self) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let Some(QualifiedState::Prelude { signer, bundle }) = self.qualified.take() else {
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
        self.qualified = Some(QualifiedState::Ack(signer));
        Ok(())
    }

    fn receive_qualified_ack(&mut self) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let Some(QualifiedState::Ack(signer)) = self.qualified.take() else {
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
