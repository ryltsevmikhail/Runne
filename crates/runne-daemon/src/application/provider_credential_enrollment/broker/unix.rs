use runne_api::ProviderCredentialEnrollmentHostError;
use runne_platform_desktop::provider_credential_broker::WriterProcessEvidence;
use runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner;
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialSecretClaimOffer, CredentialSecretPublication,
};
use zeroize::Zeroizing;

use super::CredentialBrokerChannel;

/// Daemon-owned half of the control socket created by the rendezvous authority.
///
/// Construction consumes the opaque daemon authority plus verified process
/// evidence, so ordinary callers cannot substitute an endpoint or signer.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 protected control dispatcher constructs this only after its native prompt and handoff are composed"
    )
)]
#[cfg_attr(
    all(test, not(target_os = "linux")),
    allow(dead_code, reason = "the descriptor-transfer fixture is Linux-scoped")
)]
pub(super) struct UnixCredentialBrokerChannel {
    pub(super) control: std::os::unix::net::UnixStream,
    pub(super) _evidence: WriterProcessEvidence,
    pub(super) binding: CredentialBindingDigest,
    pub(super) signer: Option<CredentialSecretPublicationSigner>,
    pub(super) publication_public_key: [u8; 32],
    pub(super) received_frames: u8,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 protected control dispatcher consumes this exact one-shot channel"
    )
)]
#[cfg_attr(
    all(test, not(target_os = "linux")),
    allow(dead_code, reason = "the descriptor-transfer fixture is Linux-scoped")
)]
impl UnixCredentialBrokerChannel {
    /// Sends one canonical daemon-to-writer frame.
    pub(super) fn send_frame(
        &mut self,
        frame: CredentialBrokerFrame,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        CredentialBrokerFrameCodec::write_to(&mut self.control, frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
    }

    /// Receives a bounded writer response in the claim/effect sequence.
    ///
    /// The protocol admits a claim followed by one possible-effect diagnostic;
    /// a third writer frame is always rejected before it is read.
    pub(super) fn receive_once(
        &mut self,
    ) -> Result<CredentialBrokerFrame, ProviderCredentialEnrollmentHostError> {
        if self.received_frames >= 2 {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.received_frames += 1;
        CredentialBrokerFrameCodec::read_from(&mut self.control)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

impl CredentialBrokerChannel for UnixCredentialBrokerChannel {
    fn binding_digest(&self) -> CredentialBindingDigest {
        self.binding
    }

    fn send(
        &mut self,
        frame: Zeroizing<Vec<u8>>,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let frame = CredentialBrokerFrameCodec::decode(&frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.send_frame(frame)
    }

    fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, ProviderCredentialEnrollmentHostError> {
        let frame = self.receive_once()?;
        CredentialBrokerFrameCodec::encode(frame)
            .map(Zeroizing::new)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    fn sign_publication(
        &mut self,
        offer: CredentialSecretClaimOffer,
    ) -> Result<CredentialSecretPublication, ProviderCredentialEnrollmentHostError> {
        let signer = self
            .signer
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if signer.public_key() != self.publication_public_key {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(signer.sign(offer))
    }
}
