use crate::credential::enrollment::CredentialEnrollmentError;

const MAGIC: &[u8; 8] = b"RNQWACK1";
const VERSION: u8 = 1;
const SEQUENCE: u64 = 2;
const BYTES: usize = 81;

/// Exact authenticated-channel acknowledgement for one qualified prelude.
pub struct CredentialWriterQualifiedAckV1 {
    pub(crate) attestation_digest: [u8; 32],
    pub(crate) prelude_digest: [u8; 32],
}

impl CredentialWriterQualifiedAckV1 {
    pub(crate) const fn new(attestation_digest: [u8; 32], prelude_digest: [u8; 32]) -> Self {
        Self {
            attestation_digest,
            prelude_digest,
        }
    }
}

/// Exact fixed-width codec for the qualified acknowledgement.
pub struct CredentialWriterQualifiedAckCodec;

impl CredentialWriterQualifiedAckCodec {
    /// Exact complete ACK length.
    pub const BYTES: usize = BYTES;

    /// Encodes the exact phase-2 acknowledgement.
    #[must_use]
    pub fn encode(value: &CredentialWriterQualifiedAckV1) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = VERSION;
        bytes[9..17].copy_from_slice(&SEQUENCE.to_be_bytes());
        bytes[17..49].copy_from_slice(&value.attestation_digest);
        bytes[49..].copy_from_slice(&value.prelude_digest);
        bytes
    }

    /// Decodes one exact ACK; channel authentication is supplied by its caller.
    pub fn decode(
        bytes: &[u8],
    ) -> Result<CredentialWriterQualifiedAckV1, CredentialEnrollmentError> {
        if bytes.len() != BYTES
            || bytes[..8] != *MAGIC
            || bytes[8] != VERSION
            || bytes[9..17] != SEQUENCE.to_be_bytes()
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Ok(CredentialWriterQualifiedAckV1 {
            attestation_digest: bytes[17..49]
                .try_into()
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
            prelude_digest: bytes[49..]
                .try_into()
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
        })
    }
}
