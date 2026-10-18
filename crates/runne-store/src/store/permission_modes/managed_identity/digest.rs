use runne_domain::id::IntegrityDigest;
use sha2::{Digest, Sha256};

const ENVELOPE_DOMAIN: &[u8] = b"runne:d21:permission-mode:issued-managed-identity:v1\0";
pub(super) const ENCODING_TAG_V2: u16 = 2;

pub(in crate::store::permission_modes) fn envelope_digest(
    legacy_issued_digest: [u8; 32],
    canonical_digest: [u8; 32],
    project_version: u64,
) -> IntegrityDigest {
    let mut hash = Sha256::new();
    hash.update(ENVELOPE_DOMAIN);
    hash.update(legacy_issued_digest);
    hash.update(ENCODING_TAG_V2.to_be_bytes());
    hash.update(canonical_digest);
    hash.update(project_version.to_be_bytes());
    IntegrityDigest::from_bytes(hash.finalize().into())
}
