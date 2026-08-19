//! Independent cryptographic RC2 update-metadata issuance approval.
#![allow(clippy::redundant_pub_crate)] // Store transaction owns sibling verifier access.

use crate::rc2_evidence_common::{
    EvidenceIdentity, EvidenceTrustBinding, FixtureEvidenceTrustState, RawRc2Evidence, verify,
};
use crate::{AuthorityError, Digest, InspectedCanonicalPayload};
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "runne.release.rc2-update-metadata-issuance/1";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Issuance {
    schema_version: String,
    signing_authorization_sha256: String,
    inventory_sha256: String,
    threshold_metadata_sha256: String,
    update_issuer: EvidenceIdentity,
    root_key_ids: Vec<String>,
    targets_key_ids: Vec<String>,
    root_threshold: u64,
    targets_threshold: u64,
    #[serde(rename = "issuance")]
    outcome: String,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
}
/// Opaque five-dimensional independent issuance acknowledgement.
#[derive(Debug, Eq, PartialEq)]
pub struct FixtureVerifiedUpdateMetadataIssuance {
    pub(crate) digest: Digest,
    pub(crate) metadata: Digest,
    pub(crate) trust: EvidenceTrustBinding,
    pub(crate) expires_at: u64,
}
///
/// # Errors
/// Returns an error unless a registered independent issuer binds the exact threshold closure.
pub(crate) fn verify_update_metadata_issuance(
    evidence: RawRc2Evidence,
    authorization: &InspectedCanonicalPayload,
    inventory: &InspectedCanonicalPayload,
    metadata: &InspectedCanonicalPayload,
    trust: &FixtureEvidenceTrustState,
) -> Result<FixtureVerifiedUpdateMetadataIssuance, AuthorityError> {
    let value: Issuance = crate::wire::strict_json::parse(&evidence.raw).and_then(|json| {
        serde_json::from_value(json).map_err(|_| AuthorityError::NonCanonicalPayload)
    })?;
    let identities = authorization
        .rc2_operational_identities()
        .ok_or(AuthorityError::BindingMismatch)?;
    let threshold = metadata
        .threshold_metadata()
        .ok_or(AuthorityError::BindingMismatch)?;
    if value.schema_version != SCHEMA
        || value.outcome != "issued"
        || value.root_threshold != 2
        || value.targets_threshold != 2
        || value.signing_authorization_sha256 != authorization.raw_digest().to_hex()
        || value.inventory_sha256 != inventory.raw_digest().to_hex()
        || value.threshold_metadata_sha256 != metadata.raw_digest().to_hex()
        || value.root_key_ids
            != threshold
                .root_keyset
                .into_iter()
                .map(|(key, _)| key)
                .collect::<Vec<_>>()
        || value.targets_key_ids
            != threshold
                .targets_keyset
                .into_iter()
                .map(|(key, _)| key)
                .collect::<Vec<_>>()
        || !value.update_issuer.matches_refs(&identities[3])
        || value.update_issuer.matches_refs(&identities[0])
        || value.update_issuer.matches_refs(&identities[1])
        || value.update_issuer.matches_refs(&identities[2])
    {
        return Err(AuthorityError::BindingMismatch);
    }
    let (_, digest) = verify::<Issuance>(
        evidence,
        trust,
        &value.update_issuer,
        value.valid_from,
        value.expires_at,
        value.revocation_epoch,
    )?;
    Ok(FixtureVerifiedUpdateMetadataIssuance {
        digest,
        metadata: metadata.raw_digest(),
        trust: trust.binding(),
        expires_at: value.expires_at,
    })
}
