mod cipher;
mod codec;
mod crypto;
mod publication;

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
