//! Independent cryptographic RC2 signing-review approval.
#![allow(clippy::redundant_pub_crate)] // Store transaction owns sibling verifier access.

use crate::native_evidence::FixtureVerifiedNativeEvidence;
use crate::rc2_evidence_common::{
    EvidenceIdentity, EvidenceTrustBinding, FixtureEvidenceTrustState, RawRc2Evidence, verify,
};
use crate::{AuthorityError, Digest, InspectedCanonicalPayload};
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "runne.release.rc2-signing-review/1";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Review {
    schema_version: String,
    signing_authorization_sha256: String,
    inventory_sha256: String,
    native_evidence_sha256: Vec<String>,
    reviewer: EvidenceIdentity,
    approval: String,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
}
/// Opaque five-dimensional independent reviewer approval.
#[derive(Debug, Eq, PartialEq)]
pub struct FixtureVerifiedSigningReview {
    pub(crate) digest: Digest,
    pub(crate) authorization: Digest,
    pub(crate) inventory: Digest,
    pub(crate) native: [(String, Digest); 3],
    pub(crate) trust: EvidenceTrustBinding,
    pub(crate) expires_at: u64,
}
///
/// # Errors
/// Returns an error unless a registered independent reviewer binds the exact closure.
pub(crate) fn verify_signing_review(
    evidence: RawRc2Evidence,
    authorization: &InspectedCanonicalPayload,
    inventory: &InspectedCanonicalPayload,
    native: &[FixtureVerifiedNativeEvidence; 3],
    trust: &FixtureEvidenceTrustState,
) -> Result<FixtureVerifiedSigningReview, AuthorityError> {
    let value: Review = crate::wire::strict_json::parse(&evidence.raw).and_then(|json| {
        serde_json::from_value(json).map_err(|_| AuthorityError::NonCanonicalPayload)
    })?;
    let identities = authorization
        .rc2_operational_identities()
        .ok_or(AuthorityError::BindingMismatch)?;
    let native_digests = native
        .iter()
        .map(|item| item.digest.to_hex())
        .collect::<Vec<_>>();
    let slots = native
        .iter()
        .map(|item| item.slot.clone())
        .collect::<Vec<_>>();
    if value.schema_version != SCHEMA
        || value.approval != "approved"
        || value.signing_authorization_sha256 != authorization.raw_digest().to_hex()
        || value.inventory_sha256 != inventory.raw_digest().to_hex()
        || value.native_evidence_sha256 != native_digests
        || slots != ["linux-appimage", "linux-deb", "windows-installer-unsigned"]
        || !value.reviewer.matches_refs(&identities[2])
        || value.reviewer.matches_refs(&identities[0])
        || value.reviewer.matches_refs(&identities[1])
        || value.reviewer.matches_refs(&identities[3])
    {
        return Err(AuthorityError::BindingMismatch);
    }
    let (_, digest) = verify::<Review>(
        evidence,
        trust,
        &value.reviewer,
        value.valid_from,
        value.expires_at,
        value.revocation_epoch,
    )?;
    Ok(FixtureVerifiedSigningReview {
        digest,
        authorization: authorization.raw_digest(),
        inventory: inventory.raw_digest(),
        native: std::array::from_fn(|index| (native[index].slot.clone(), native[index].digest)),
        trust: trust.binding(),
        expires_at: value.expires_at,
    })
}
