//! Strict raw V3 verification boundary for production V2 trust.

use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, PurposeProfileV3, VerifiedDocumentReconciliation, VerifiedInitialAuthorization,
    VerifiedTrustConfigV2, receipt_v3::verified_document_reconciliation,
    receipt_v3_v2::verify_receipt_v3_v2, receipt_v3_wire::receipt_from_bytes,
};

/// Verify canonical checked-in V3 bytes against V2 trust; V1 cannot enter this boundary.
///
/// # Errors
/// Returns a fail-closed error for byte, V2 trust, predecessor, or signature mismatch.
pub fn verify_receipt_v3_bytes(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    profile: &PurposeProfileV3,
    trust: &VerifiedTrustConfigV2,
    predecessor: &VerifiedInitialAuthorization,
) -> Result<VerifiedDocumentReconciliation, AuthorityError> {
    if <[u8; 32]>::from(Sha256::digest(bytes)) != expected_sha256 {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    verify_receipt_v3_v2(&receipt_from_bytes(bytes)?, profile, trust, predecessor)?;
    verified_document_reconciliation(expected_sha256, trust.config())
}
