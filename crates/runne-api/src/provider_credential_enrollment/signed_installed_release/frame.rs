use super::verification::{SignedInstalledReleaseVerificationErrorV2, decode_canonical_metadata};

const MAGIC: &[u8; 8] = b"GCRMDV2\0";
const MAX_PAYLOAD_BYTES: usize = 524_288;

pub struct PendingSignedInstalledReleaseMetadataV2 {
    // Intentionally retained for the consuming pinned-trust transition in B2b3-ii.
    #[allow(dead_code)]
    canonical_metadata: Vec<u8>,
}

impl PendingSignedInstalledReleaseMetadataV2 {
    #[doc(hidden)]
    pub fn read_from<R: std::io::Read>(
        reader: &mut R,
    ) -> Result<Self, SignedInstalledReleaseVerificationErrorV2> {
        let mut magic = [0_u8; MAGIC.len()];
        reader
            .read_exact(&mut magic)
            .map_err(|_| SignedInstalledReleaseVerificationErrorV2::InvalidEncoding)?;
        if &magic != MAGIC {
            return Err(SignedInstalledReleaseVerificationErrorV2::InvalidEncoding);
        }

        let mut encoded_length = [0_u8; size_of::<u32>()];
        reader
            .read_exact(&mut encoded_length)
            .map_err(|_| SignedInstalledReleaseVerificationErrorV2::InvalidEncoding)?;
        let payload_length = u32::from_be_bytes(encoded_length) as usize;
        if payload_length == 0 {
            return Err(SignedInstalledReleaseVerificationErrorV2::InvalidEncoding);
        }
        if payload_length > MAX_PAYLOAD_BYTES {
            return Err(SignedInstalledReleaseVerificationErrorV2::MetadataTooLarge);
        }

        let mut canonical_metadata = vec![0_u8; payload_length];
        reader
            .read_exact(&mut canonical_metadata)
            .map_err(|_| SignedInstalledReleaseVerificationErrorV2::InvalidEncoding)?;
        let _ = decode_canonical_metadata(&canonical_metadata)?;

        Ok(PendingSignedInstalledReleaseMetadataV2 { canonical_metadata })
    }
}
