mod cipher;
mod codec;
mod crypto;
mod publication;
mod relay;
mod relay_frame;

#[cfg(test)]
mod tests;

pub use codec::{CredentialSecretEnvelopeCodec, CredentialSecretOfferCodec};
pub use crypto::{
    CredentialSecretClaimOffer, PendingCredentialSecretOpening, SealedCredentialEnvelope,
};
#[doc(hidden)]
pub use publication::CredentialSecretPublicationSigner as DaemonCredentialSecretPublicationSigner;
#[cfg(feature = "test-support")]
pub(crate) use publication::verify_for_test as verify_publication_for_test;
pub use publication::{CredentialSecretPublication, CredentialSecretPublicationCodec};
pub use relay_frame::CredentialSecretRelayFrameCodec;

#[cfg(feature = "platform-desktop-internal")]
#[doc(hidden)]
pub mod platform_desktop_internal {
    pub use super::relay_frame::AuthenticatedCredentialSecretRelaySealer;
}

/// Test-only sealed Pair relay with no signer or verifier escape hatch.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub struct SealedPairFixture {
    /// One move-only opening capability bound to the fixture tuple.
    pub pending: PendingCredentialSecretOpening,
    /// One exact sealed credential envelope for that opening capability.
    pub envelope: SealedCredentialEnvelope,
}

/// Builds one fully verified relay for a known test command and channel.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn sealed_pair_for_test(
    command: &super::CredentialBrokerCommand,
    binding: super::CredentialBindingDigest,
    channel: &crate::credential::enrollment::BrokerChannelBinding,
    secret: Vec<u8>,
) -> Result<SealedPairFixture, crate::credential::enrollment::CredentialEnrollmentError> {
    let (offer, pending) = CredentialSecretClaimOffer::prepare(command, binding)?;
    let verified_offer =
        CredentialSecretOfferCodec::decode(&CredentialSecretOfferCodec::encode(&offer))?;
    let signer = super::session_attestation::attested_publication_signer_for_test(channel, &offer)?;
    let public_key = signer.public_key();
    let publication = signer.sign(offer, channel.digest())?;
    let verified = publication::CredentialSecretPublicationVerifier::new(public_key, channel)
        .verify(verified_offer, publication)?;
    let envelope = verified.seal(zeroize::Zeroizing::new(secret))?;
    Ok(SealedPairFixture { pending, envelope })
}
