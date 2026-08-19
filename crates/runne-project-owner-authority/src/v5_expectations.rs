//! Independent opaque inputs for receipt `/5` expected bindings.

use sha2::{Digest, Sha256};

use crate::{AuthorityError, ExpectedReceiptV5Bindings, GitSubject};

/// Opaque independently verified production-security-review instance.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedProductionSecurityReviewInstance {
    digest: [u8; 32],
}

/// Opaque Git subject retained from a cryptographically validated predecessor.
#[derive(Debug, Eq, PartialEq)]
pub struct ResolvedGitSubject {
    subject: GitSubject,
}

/// Independent production-security-review verification boundary.
pub trait ProductionSecurityReviewVerificationContext {
    /// Verify the exact canonical review instance rather than a caller-supplied digest.
    ///
    /// # Errors
    /// Returns an error unless the instance has passed the independent review authority.
    fn verify_production_security_review(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<(), AuthorityError>;
}

/// Trusted Git resolver boundary used before pure receipt-chain composition.
pub trait GitSubjectResolutionContext {
    /// Resolve the exact repository commit/tree identity from the trusted Git object store.
    ///
    /// # Errors
    /// Returns an error when the repository subject cannot be resolved authoritatively.
    fn resolve_git_subject(&self) -> Result<GitSubject, AuthorityError>;
}

/// Verify a canonical production-security-review instance and mint its opaque handle.
///
/// The digest is always derived from the verified bytes and cannot be supplied by the caller.
///
/// # Errors
/// Returns an error for noncanonical/wrong-version input or independent verification failure.
pub fn verify_production_security_review_instance(
    canonical_bytes: &[u8],
    context: &dyn ProductionSecurityReviewVerificationContext,
) -> Result<VerifiedProductionSecurityReviewInstance, AuthorityError> {
    let value = crate::strict_json::parse(canonical_bytes)?;
    if value
        .as_object()
        .and_then(|object| object.get("schema_version"))
        .and_then(serde_json::Value::as_str)
        != Some("runne.rc0.production-security-review/1")
        || serde_json::to_vec(&value).map_err(|_| AuthorityError::Serialization)? != canonical_bytes
    {
        return Err(AuthorityError::InvalidReceipt);
    }
    context.verify_production_security_review(canonical_bytes)?;
    Ok(VerifiedProductionSecurityReviewInstance {
        digest: Sha256::digest(canonical_bytes).into(),
    })
}

/// Resolve and bind the Git subject to a cryptographically validated V4 lineage.
///
/// # Errors
/// Returns an error unless the independently resolved subject exactly matches V4.
pub fn resolve_git_subject(
    predecessor: &impl crate::PromotionBootstrapV4Lineage,
    context: &dyn GitSubjectResolutionContext,
) -> Result<ResolvedGitSubject, AuthorityError> {
    let subject = context.resolve_git_subject()?;
    crate::receipt_validation::subject_oid_width(&subject)?;
    if &subject != crate::v5_lineage::v4_lineage(predecessor).subject {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    Ok(ResolvedGitSubject { subject })
}

/// Build receipt `/5` expectations exclusively from independently verified opaque handles.
///
/// ```compile_fail
/// use runne_project_owner_authority::expected_receipt_v5_bindings;
/// let _ = expected_receipt_v5_bindings(&[0; 32], &Default::default(), &[0; 32], 1);
/// ```
#[must_use]
pub fn expected_receipt_v5_bindings(
    review: &VerifiedProductionSecurityReviewInstance,
    subject: &ResolvedGitSubject,
    allowlist: &crate::PrevalidatedRootSignedDestinationAllowlistV1,
) -> ExpectedReceiptV5Bindings {
    ExpectedReceiptV5Bindings {
        production_security_review_sha256: review.digest,
        subject: subject.subject.clone(),
        destination_allowlist_unsigned_sha256: allowlist.unsigned_sha256,
        destination_allowlist_generation: allowlist.value.generation,
    }
}
