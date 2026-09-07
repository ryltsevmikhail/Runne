mod ack;
mod claims;
mod codec;
mod prelude;
mod receiver;
mod signer;

pub use ack::{CredentialWriterQualifiedAckCodec, CredentialWriterQualifiedAckV1};
pub use claims::SignedCredentialWriterSessionAttestationV2;
pub use codec::CredentialWriterSessionAttestationV2Codec;
pub use prelude::{CredentialWriterQualifiedPreludeCodec, CredentialWriterQualifiedPreludeV1};
pub(crate) use receiver::VerifiedWriterQualificationFault;
pub(super) use receiver::WriterQualificationReceiver;
pub use signer::{CredentialWriterQualifiedAckSigner, CredentialWriterQualifiedPreludeSigner};

pub(super) fn signature_message(value: &SignedCredentialWriterSessionAttestationV2) -> Vec<u8> {
    codec::CredentialWriterSessionAttestationV2Codec::signature_message(value)
}
