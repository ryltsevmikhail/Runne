//! Specialized evidence-envelope `/2` verification entrypoints.

use crate::{
    AuthorityError, V5EnvelopeVerificationContext, VerifiedPromotionBootstrapV5,
    VerifiedRc3FinalReviewEvidence,
};

/// Verify evidence restricted to the `(RC3_FINAL_REVIEWER, final-review)` scope.
///
/// # Errors
/// Returns generic evidence verification errors or rejects a different retained
/// issuer role, scope, or payload schema after admission.
pub fn verify_rc3_final_review_evidence_v2(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    receipt5: &VerifiedPromotionBootstrapV5,
    context: &dyn V5EnvelopeVerificationContext,
) -> Result<VerifiedRc3FinalReviewEvidence, AuthorityError> {
    let verified = crate::verify_evidence_envelope_v2(bytes, expected_sha256, receipt5, context)?;
    if verified.issuer().role != "RC3_FINAL_REVIEWER"
        || verified.issuer().scope != "final-review"
        || verified.payload_schema_id() != "runne.release.rc3-final-review/1"
    {
        return Err(AuthorityError::InvalidEvidenceEnvelope);
    }
    Ok(verified)
}
