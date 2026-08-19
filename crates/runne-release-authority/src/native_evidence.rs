//! Fixture-only cryptographic Linux/Windows native evidence boundary.
#![allow(clippy::missing_errors_doc)] // Fixture-only lease completion wrapper.
#![allow(clippy::redundant_pub_crate)] // Store transaction owns sibling verifier access.

use serde::{Deserialize, Serialize};

use crate::rc2_evidence_common::{
    EvidenceIdentity, EvidenceTrustBinding, FixtureEvidenceTrustState, RawRc2Evidence,
    valid_identifier, verify,
};
use crate::signing_effect_evidence::{
    FixtureInFlightSigningEffect, FixtureVerifiedSigningEffect, hex,
};
use crate::{AuthorityError, CanonicalPayloadKind, Digest, InspectedCanonicalPayload};

const SCHEMA: &str = "runne.release.rc2-native-evidence/1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeEvidence {
    schema_version: String,
    signed_artifact_record_sha256: String,
    signing_effect_claim_sha256: String,
    parent_candidate_sha256: String,
    artifact_slot_id: String,
    platform: String,
    host_id: String,
    build_id: String,
    architecture: String,
    post_sign_artifact_sha256: String,
    post_sign_artifact_length: u64,
    attestations: Vec<NativeAttestation>,
    runner: EvidenceIdentity,
    result: String,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeAttestation {
    kind: String,
    result: String,
    artifact_sha256: String,
    result_sha256: String,
}

const ATTESTATION_KINDS: [&str; 10] = [
    "native_signature",
    "certificate_chain",
    "timestamp",
    "secret_scan",
    "advisory_scan",
    "package_inspection",
    "install",
    "upgrade",
    "rollback",
    "uninstall",
];

/// Opaque evidence that only a registered native runner may mint for one signed record.
#[derive(Debug, Eq, PartialEq)]
pub struct FixtureVerifiedNativeEvidence {
    pub(crate) digest: Digest,
    pub(crate) record: Digest,
    pub(crate) effect: Digest,
    pub(crate) candidate: Digest,
    pub(crate) slot: String,
    pub(crate) platform: String,
    pub(crate) trust: EvidenceTrustBinding,
    pub(crate) expires_at: u64,
}

/// Verify raw canonical native evidence; fixture signatures never provision production signing.
///
/// # Errors
/// Returns an error unless all Linux/Windows proof fields bind one exact record and effect claim.
pub(crate) fn verify_native_evidence(
    evidence: RawRc2Evidence,
    record: &InspectedCanonicalPayload,
    effect: &FixtureVerifiedSigningEffect,
    trust: &FixtureEvidenceTrustState,
) -> Result<FixtureVerifiedNativeEvidence, AuthorityError> {
    let value: NativeEvidence =
        crate::wire::strict_json::parse(&evidence.raw).and_then(|json| {
            serde_json::from_value(json).map_err(|_| AuthorityError::NonCanonicalPayload)
        })?;
    let parts = record
        .artifact_record()
        .ok_or(AuthorityError::BindingMismatch)?;
    if record.kind() != CanonicalPayloadKind::ArtifactRecord
        || value.schema_version != SCHEMA
        || value.result != "verified"
        || !matches!(value.platform.as_str(), "linux" | "windows")
        || value.platform != parts.platform
        || value.artifact_slot_id != parts.artifact_slot_id
        || value.parent_candidate_sha256 != parts.candidate.to_hex()
        || value.signed_artifact_record_sha256 != record.raw_digest().to_hex()
        || value.signing_effect_claim_sha256 != effect.digest.to_hex()
        || value.post_sign_artifact_sha256 != parts.artifact.to_hex()
        || value.post_sign_artifact_length != parts.artifact_length
        || value.runner != effect.runner
        || effect.candidate != parts.candidate.to_hex()
        || effect.slot != parts.artifact_slot_id
        || effect.platform != parts.platform
        || effect.pre_sign != parts.pre_sign_digest.to_hex()
        || effect.pre_sign_length != parts.pre_sign_length
        || effect.authorization != parts.authorization.to_hex()
        || effect.workflow != parts.workflow.to_hex()
        || !effect.signer.matches_parts(&parts.signer)
        || !effect.runner.matches_parts(&parts.runner)
        || effect.namespace != parts.effect_namespace
        || effect.generation != parts.effect_generation
        || !value.runner.valid()
        || ![&value.host_id, &value.build_id, &value.architecture]
            .into_iter()
            .all(|id| valid_identifier(id))
        || value.attestations.len() != ATTESTATION_KINDS.len()
        || value
            .attestations
            .iter()
            .zip(ATTESTATION_KINDS)
            .any(|(item, kind)| {
                item.kind != kind
                    || item.result != "verified"
                    || item.artifact_sha256 != parts.artifact.to_hex()
                    || !hex(&item.result_sha256)
            })
        || value
            .attestations
            .iter()
            .map(|item| &item.result_sha256)
            .ne(parts
                .attestations
                .iter()
                .map(|digest| digest.to_hex())
                .collect::<Vec<_>>()
                .iter())
    {
        return Err(AuthorityError::BindingMismatch);
    }
    let (value, digest) = verify::<NativeEvidence>(
        evidence,
        trust,
        &value.runner,
        value.valid_from,
        value.expires_at,
        value.revocation_epoch,
    )?;
    Ok(FixtureVerifiedNativeEvidence {
        digest,
        record: record.raw_digest(),
        effect: effect.digest,
        candidate: parts.candidate,
        slot: value.artifact_slot_id,
        platform: value.platform,
        trust: trust.binding(),
        expires_at: value.expires_at,
    })
}

/// Verify native evidence and close the exact in-flight signing slot lease.
pub(crate) fn verify_native_evidence_closing_lease(
    evidence: RawRc2Evidence,
    record: &InspectedCanonicalPayload,
    effect: FixtureInFlightSigningEffect,
    trust: &FixtureEvidenceTrustState,
    ledger: &mut crate::FixtureRc2EffectLeaseLedger,
) -> Result<FixtureVerifiedNativeEvidence, AuthorityError> {
    let verified = verify_native_evidence(evidence, record, &effect.effect, trust)?;
    ledger
        .complete(effect.lease)
        .map_err(|_| AuthorityError::BindingMismatch)?;
    Ok(verified)
}

pub(crate) fn replay_native_evidence(
    evidence: RawRc2Evidence,
    record: &InspectedCanonicalPayload,
    effect: &FixtureInFlightSigningEffect,
    trust: &FixtureEvidenceTrustState,
    ledger: &crate::FixtureRc2EffectLeaseLedger,
) -> Result<FixtureVerifiedNativeEvidence, AuthorityError> {
    let verified = verify_native_evidence(evidence, record, &effect.effect, trust)?;
    ledger
        .has_state(&effect.lease, crate::Rc2SigningEffectLeaseState::Completed)
        .map_err(|_| AuthorityError::BindingMismatch)?;
    Ok(verified)
}

impl FixtureVerifiedNativeEvidence {
    #[must_use]
    pub const fn sha256(&self) -> Digest {
        self.digest
    }
    pub(crate) fn matches(
        &self,
        record: &InspectedCanonicalPayload,
        effect: &FixtureVerifiedSigningEffect,
    ) -> bool {
        self.record == record.raw_digest()
            && self.effect == effect.digest
            && self.trust == effect.trust
    }
}
