use runne_domain::DigestEqualityMatcherV1;

use super::binding::{VerifiedSignedInstalledReleaseV2, exact_with_matcher};
use super::compiled_trust::CompiledUpdateTrustRootV2;
use super::model::UpdateTrustRootV2;
use super::verification::{
    SignedInstalledReleaseVerificationErrorV2, decode_canonical_metadata,
    verify_signed_update_metadata_v2,
};

const MAGIC: &[u8; 8] = b"GCRMDV2\0";
const MAX_PAYLOAD_BYTES: usize = 524_288;

pub struct PendingSignedInstalledReleaseMetadataV2 {
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

    /// Verifies this frame using only compiled trust and the process wall clock.
    ///
    /// # Errors
    ///
    /// Returns a closed verification error for absent trust, invalid time, metadata,
    /// signatures, qualification, or an unequal release binding.
    #[doc(hidden)]
    pub fn verify_current_pinned(
        self,
        expected: DigestEqualityMatcherV1,
    ) -> Result<VerifiedSignedInstalledReleaseV2, SignedInstalledReleaseVerificationErrorV2> {
        let trust = CompiledUpdateTrustRootV2::load()
            .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidTrustRoot)?
            .into_trust_root();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| SignedInstalledReleaseVerificationErrorV2::Expired)?
            .as_secs();
        verify_current_pinned_with(self, &trust, now, &expected)
    }
}

fn verify_current_pinned_with(
    pending: PendingSignedInstalledReleaseMetadataV2,
    trust: &UpdateTrustRootV2,
    now: u64,
    expected: &DigestEqualityMatcherV1,
) -> Result<VerifiedSignedInstalledReleaseV2, SignedInstalledReleaseVerificationErrorV2> {
    let metadata = decode_canonical_metadata(&pending.canonical_metadata)?;
    exact_with_matcher(
        verify_signed_update_metadata_v2(&metadata, trust, now)?,
        expected,
    )
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;
