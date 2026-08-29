use std::io::Read;

use runne_provider::{CredentialSecretEnvelopeCodec, SealedCredentialEnvelope};
use zeroize::Zeroizing;

use super::CliError;

/// Reads exactly one bounded sealed Pair envelope to EOF.
///
/// The only decoder is the typed secret relay codec. Partial, invalid, oversized,
/// or trailing input fails before a native writer effect can begin.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the authenticated inherited-channel runner is composed after the platform handoff"
    )
)]
pub fn read_sealed_pair_envelope(
    reader: &mut impl Read,
) -> Result<SealedCredentialEnvelope, CliError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(CredentialSecretEnvelopeCodec::MAX_BYTES));
    loop {
        let mut byte = [0_u8; 1];
        match reader
            .read(&mut byte)
            .map_err(|_| CliError::CredentialOperation)?
        {
            0 => break,
            1 => {
                if bytes.len() == CredentialSecretEnvelopeCodec::MAX_BYTES {
                    return Err(CliError::CredentialOperation);
                }
                bytes.push(byte[0]);
            }
            _ => return Err(CliError::CredentialOperation),
        }
    }
    CredentialSecretEnvelopeCodec::decode(&bytes).map_err(|_| CliError::CredentialOperation)
}
