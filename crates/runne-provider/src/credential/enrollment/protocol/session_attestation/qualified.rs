mod ack;
mod claims;
mod codec;
#[cfg(target_os = "linux")]
mod linux_writer_start;
mod prelude;
mod receiver;
mod signer;

pub use ack::{CredentialWriterQualifiedAckCodec, CredentialWriterQualifiedAckV1};
pub use claims::SignedCredentialWriterSessionAttestationV2;
pub use codec::CredentialWriterSessionAttestationV2Codec;
#[cfg(target_os = "linux")]
pub use linux_writer_start::{
    LinuxWriterStartup, encode_linux_writer_startup_payload, linux_writer_self_measurements,
    respond_linux_writer_startup,
};
pub use prelude::{CredentialWriterQualifiedPreludeCodec, CredentialWriterQualifiedPreludeV1};
pub(crate) use receiver::VerifiedWriterQualificationFault;
pub(super) use receiver::WriterQualificationReceiver;
pub use signer::{CredentialWriterQualifiedAckSigner, CredentialWriterQualifiedPreludeSigner};

pub(super) fn signature_message(value: &SignedCredentialWriterSessionAttestationV2) -> Vec<u8> {
    codec::CredentialWriterSessionAttestationV2Codec::signature_message(value)
}
