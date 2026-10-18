use std::collections::VecDeque;

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    CredentialSecretClaimOffer, CredentialWriterSessionAttestationClaimsV1,
    daemon_credential_publication::CredentialWriterSessionAttestationSigner,
};
use zeroize::Zeroizing;

use crate::application::provider_credential_enrollment::broker::CredentialBrokerChannel;
use crate::application::provider_credential_enrollment::broker::writer_session_test_support::writer_session_claims;

pub(crate) struct RecordingChannel {
    pub(crate) frames: Vec<Vec<u8>>,
    received: VecDeque<Zeroizing<Vec<u8>>>,
    fail_send: bool,
    binding: runne_provider::CredentialBindingDigest,
    attestation_signer: Option<CredentialWriterSessionAttestationSigner>,
    attestation_claims: Option<CredentialWriterSessionAttestationClaimsV1>,
    publication_public_key: [u8; 32],
    pub(crate) sign_invocations: u8,
    pub(crate) receive_calls: u8,
}

impl RecordingChannel {
    pub(crate) fn with_channel_binding(binding: [u8; 32]) -> Self {
        let signer = CredentialWriterSessionAttestationSigner::generate(binding).unwrap();
        let publication_public_key = signer.public_key();
        Self {
            frames: Vec::new(),
            received: VecDeque::new(),
            fail_send: false,
            binding: runne_provider::CredentialBindingDigest::from_measured(binding).unwrap(),
            attestation_signer: Some(signer),
            attestation_claims: None,
            publication_public_key,
            sign_invocations: 0,
            receive_calls: 0,
        }
    }

    pub(crate) fn queue_received(&mut self, frame: Zeroizing<Vec<u8>>) {
        self.received.push_back(frame);
    }

    pub(crate) fn fail_next_send(&mut self) {
        self.fail_send = true;
    }

    pub(crate) const fn publication_public_key(&self) -> [u8; 32] {
        self.publication_public_key
    }
}

impl Default for RecordingChannel {
    fn default() -> Self {
        Self::with_channel_binding([21; 32])
    }
}

impl CredentialBrokerChannel for RecordingChannel {
    fn binding_digest(&self) -> runne_provider::CredentialBindingDigest {
        self.binding
    }

    fn send_issue(
        &mut self,
        _receipt: &runne_provider::IssuedCredentialTicketAttempt,
        frame: runne_provider::CredentialBrokerFrame,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let encoded = runne_provider::CredentialBrokerFrameCodec::encode(frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.send(Zeroizing::new(encoded))
    }

    fn send(
        &mut self,
        frame: Zeroizing<Vec<u8>>,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        if std::mem::take(&mut self.fail_send) {
            return Err(ProviderCredentialEnrollmentHostError::Unavailable);
        }
        let decoded = runne_provider::CredentialBrokerFrameCodec::decode(&frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if matches!(
            decoded,
            runne_provider::CredentialBrokerFrame::IssueTicket { .. }
        ) {
            self.attestation_claims = Some(
                writer_session_claims(&decoded)
                    .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
            );
        }
        self.frames.push(frame.to_vec());
        Ok(())
    }

    fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, ProviderCredentialEnrollmentHostError> {
        self.receive_calls = self.receive_calls.saturating_add(1);
        self.received
            .pop_front()
            .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)
    }

    fn sign_publication(
        &mut self,
        offer: CredentialSecretClaimOffer,
    ) -> Result<runne_provider::CredentialSecretPublication, ProviderCredentialEnrollmentHostError>
    {
        let signer = self
            .attestation_signer
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let claims = self
            .attestation_claims
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let (_, signer) = signer
            .sign(claims)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.sign_invocations = self.sign_invocations.saturating_add(1);
        signer
            .sign(offer, self.binding)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}
