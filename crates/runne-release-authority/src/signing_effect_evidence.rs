//! Authenticated RC2 signing-effect claim validation.
#![allow(clippy::redundant_pub_crate)] // Native evidence consumes this crate-private verifier.
#![allow(clippy::missing_errors_doc)] // Fixture-only leased verification APIs.

use serde::{Deserialize, Serialize};

use crate::rc2_evidence_common::{
    EvidenceIdentity, EvidenceTrustBinding, FixtureEvidenceTrustState, RawRc2Evidence,
    valid_identifier, verify,
};
use crate::{AuthorityError, CanonicalPayloadKind, Digest, InspectedCanonicalPayload};

const SCHEMA: &str = "gocode.release.rc2-signing-effect-claim/1";
const READBACK_SCHEMA: &str = "gocode.release.rc2-signing-backend-readback/1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    schema_version: String,
    signing_authorization_sha256: String,
    parent_candidate_sha256: String,
    artifact_slot_id: String,
    platform: String,
    pre_sign_artifact_sha256: String,
    pre_sign_artifact_length: u64,
    signer: EvidenceIdentity,
    runner: EvidenceIdentity,
    workflow_sha256: String,
    effect_namespace: String,
    effect_generation: u64,
    generation_fence: u64,
    operation: String,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackendReadback {
    schema_version: String,
    signing_authorization_sha256: String,
    artifact_slot_id: String,
    pre_sign_artifact_sha256: String,
    effect_generation: u64,
    outcome: String,
    runner: EvidenceIdentity,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
}

/// Opaque, non-cloneable authenticated signing effect bound to one exact slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureVerifiedSigningEffect {
    pub(crate) digest: Digest,
    pub(crate) authorization: String,
    pub(crate) candidate: String,
    pub(crate) slot: String,
    pub(crate) platform: String,
    pub(crate) pre_sign: String,
    pub(crate) pre_sign_length: u64,
    pub(crate) signer: EvidenceIdentity,
    pub(crate) runner: EvidenceIdentity,
    pub(crate) workflow: String,
    pub(crate) namespace: String,
    pub(crate) generation: u64,
    pub(crate) trust: EvidenceTrustBinding,
    pub(crate) expires_at: u64,
}
/// Exact in-flight slot lease consumed by a verified raw signing claim.
#[derive(Debug, Eq, PartialEq)]
pub struct FixtureInFlightSigningEffect {
    pub(crate) effect: FixtureVerifiedSigningEffect,
    pub(crate) lease: crate::FixtureRc2SigningDispatchLease,
}

impl FixtureInFlightSigningEffect {
    #[must_use]
    pub const fn effect(&self) -> &FixtureVerifiedSigningEffect {
        &self.effect
    }
}
impl FixtureVerifiedSigningEffect {
    #[must_use]
    pub const fn sha256(&self) -> Digest {
        self.digest
    }
}

/// Verify canonical raw claim bytes using a registered signer key and trusted time/revocation.
///
/// # Errors
/// Returns an error for malformed, stale, unregistered, substituted, or wrongly signed claims.
pub(crate) fn verify_signing_effect_claim(
    evidence: RawRc2Evidence,
    authorization: &InspectedCanonicalPayload,
    trust: &FixtureEvidenceTrustState,
) -> Result<FixtureVerifiedSigningEffect, AuthorityError> {
    let value: Claim = crate::wire::strict_json::parse(&evidence.raw).and_then(|json| {
        serde_json::from_value(json).map_err(|_| AuthorityError::NonCanonicalPayload)
    })?;
    let plan = authorization
        .rc2_plan()
        .ok_or(AuthorityError::BindingMismatch)?;
    let expected = plan
        .artifacts
        .iter()
        .find(|(slot, _, _, _)| *slot == value.artifact_slot_id)
        .ok_or(AuthorityError::BindingMismatch)?;
    if authorization.kind() != CanonicalPayloadKind::Rc2Authorization
        || value.schema_version != SCHEMA
        || value.effect_generation == 0
        || value.generation_fence != value.effect_generation
        || value.operation != "native_sign"
        || !matches!(value.platform.as_str(), "linux" | "windows")
        || !value.runner.valid()
        || value.signer == value.runner
        || !hex(&value.signing_authorization_sha256)
        || !hex(&value.parent_candidate_sha256)
        || !hex(&value.pre_sign_artifact_sha256)
        || !hex(&value.workflow_sha256)
        || !valid_identifier(&value.artifact_slot_id)
        || !valid_identifier(&value.effect_namespace)
    {
        return Err(AuthorityError::BindingMismatch);
    }
    if value.signing_authorization_sha256 != authorization.raw_digest().to_hex()
        || value.parent_candidate_sha256 != plan.candidate.to_hex()
        || value.platform != expected.1
        || value.pre_sign_artifact_sha256 != expected.2.to_hex()
        || value.pre_sign_artifact_length != expected.3
        || !value.signer.matches_parts(&plan.signer)
        || !value.runner.matches_parts(&plan.runner)
        || value.workflow_sha256 != plan.workflow.to_hex()
        || value.effect_namespace != plan.effect_namespace
        || value.effect_generation != plan.effect_generation
    {
        return Err(AuthorityError::BindingMismatch);
    }
    let (value, digest) = verify::<Claim>(
        evidence,
        trust,
        &value.signer,
        value.valid_from,
        value.expires_at,
        value.revocation_epoch,
    )?;
    Ok(FixtureVerifiedSigningEffect {
        digest,
        authorization: value.signing_authorization_sha256,
        candidate: value.parent_candidate_sha256,
        slot: value.artifact_slot_id,
        platform: value.platform,
        pre_sign: value.pre_sign_artifact_sha256,
        pre_sign_length: value.pre_sign_artifact_length,
        signer: value.signer,
        runner: value.runner,
        workflow: value.workflow_sha256,
        namespace: value.effect_namespace,
        generation: value.effect_generation,
        trust: trust.binding(),
        expires_at: value.expires_at,
    })
}

/// Verify raw signing evidence only while consuming the matching claimed slot lease.
pub(crate) fn verify_signing_effect_claim_with_lease(
    evidence: RawRc2Evidence,
    authorization: &InspectedCanonicalPayload,
    trust: &FixtureEvidenceTrustState,
    ledger: &mut crate::FixtureRc2EffectLeaseLedger,
    lease: crate::FixtureRc2SigningDispatchLease,
) -> Result<FixtureInFlightSigningEffect, AuthorityError> {
    let effect = verify_signing_effect_claim(evidence, authorization, trust)?;
    if effect.slot != lease.slot() {
        return Err(AuthorityError::BindingMismatch);
    }
    let (now, epoch) = trust.timing();
    let lease = ledger
        .dispatch(lease, now, epoch)
        .map_err(|_| AuthorityError::BindingMismatch)?;
    Ok(FixtureInFlightSigningEffect { effect, lease })
}

pub(crate) fn replay_signing_effect_claim(
    evidence: RawRc2Evidence,
    authorization: &InspectedCanonicalPayload,
    trust: &FixtureEvidenceTrustState,
    ledger: &crate::FixtureRc2EffectLeaseLedger,
    lease: crate::FixtureRc2SigningDispatchLease,
) -> Result<FixtureInFlightSigningEffect, AuthorityError> {
    let effect = verify_signing_effect_claim(evidence, authorization, trust)?;
    if effect.slot != lease.slot() {
        return Err(AuthorityError::BindingMismatch);
    }
    ledger
        .has_replay_state(&lease)
        .map_err(|_| AuthorityError::BindingMismatch)?;
    Ok(FixtureInFlightSigningEffect { effect, lease })
}

/// Verify signed opaque backend readback before permitting uncertain-claim reconciliation.
pub(crate) fn verify_signing_backend_readback(
    evidence: RawRc2Evidence,
    trust: &FixtureEvidenceTrustState,
    lease: &crate::FixtureRc2SigningDispatchLease,
) -> Result<crate::Rc2SigningBackendReadbackFixture, AuthorityError> {
    let value: BackendReadback =
        crate::wire::strict_json::parse(&evidence.raw).and_then(|json| {
            serde_json::from_value(json).map_err(|_| AuthorityError::NonCanonicalPayload)
        })?;
    if value.schema_version != READBACK_SCHEMA
        || value.signing_authorization_sha256 != lease.authorization().to_hex()
        || value.artifact_slot_id != lease.slot()
        || value.effect_generation != lease.generation()
        || !hex(&value.pre_sign_artifact_sha256)
        || !matches!(
            value.outcome.as_str(),
            "succeeded" | "absent" | "inconclusive"
        )
    {
        return Err(AuthorityError::BindingMismatch);
    }
    let (value, _) = verify::<BackendReadback>(
        evidence,
        trust,
        &value.runner,
        value.valid_from,
        value.expires_at,
        value.revocation_epoch,
    )?;
    crate::Rc2SigningBackendReadbackFixture::verified(
        value.artifact_slot_id,
        value.pre_sign_artifact_sha256,
        identity_key(&value.runner),
        &value.outcome,
    )
    .map_err(|_| AuthorityError::BindingMismatch)
}

fn identity_key(identity: &EvidenceIdentity) -> String {
    format!(
        "{}/{}/{}/{}/{}",
        identity.principal_id,
        identity.account_id,
        identity.lane_id,
        identity.key_id,
        identity.signature_profile_id,
    )
}

pub(crate) fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|x| x.is_ascii_hexdigit() && !x.is_ascii_uppercase())
}
