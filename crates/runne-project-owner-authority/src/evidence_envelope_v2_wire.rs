//! Strict raw evidence-envelope `/2` verification against a verified receipt `/5`.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::evidence_envelope_v2_codec::{hex_array, signature};
use crate::{
    AuthorityError, EVIDENCE_ENVELOPE_SCHEMA_V2, EnvelopeValidityV2, EvidenceAuthorityEnvelopeV2,
    PrevalidatedEvidenceEnvelopeV2, V5AdmissionScope, V5EnvelopeVerificationContext,
    VerifiedEvidenceEnvelopeV2, VerifiedPromotionBootstrapV5, canonical_stage_payload,
    framed_transcript,
    receipt_v4_validation::{hex_digest, safe_id},
    receipt_validation::valid_timestamp,
    trust_canonical::hex,
};

/// Length-framed domain separation for evidence-envelope `/2` detached signatures.
const DOMAIN_V2: &[u8] = b"gocode.release.post-rc0-evidence-envelope/2";

/// Verify canonical raw evidence-envelope `/2` bytes and mint a move-only handle.
///
/// The exact receipt `/5` evidence `(role, scope)` delegation is matched before
/// any trusted context call; the context is invoked only after structural, pin,
/// and signature checks succeed.
/// # Errors
/// Returns `AUTHORITY_VERSION_SUPERSEDED` for legacy/mixed versions, rejects
/// noncanonical, unauthentic, or divergent input before context admission, and
/// propagates trusted-context admission failures.
pub fn verify_evidence_envelope_v2(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    receipt5: &VerifiedPromotionBootstrapV5,
    context: &dyn V5EnvelopeVerificationContext,
) -> Result<VerifiedEvidenceEnvelopeV2, AuthorityError> {
    crate::admit_prevalidated_evidence_envelope_v2(
        prevalidate_evidence_envelope_v2(bytes, expected_sha256, receipt5)?,
        context,
    )
}

/// Verify evidence-envelope `/2` bytes without trusted-context admission.
/// # Errors
/// Returns only canonical, digest, pin, delegation, signature, or binding errors.
pub fn prevalidate_evidence_envelope_v2(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    receipt5: &impl crate::PromotionAuthorityReceiptV5Lineage,
) -> Result<PrevalidatedEvidenceEnvelopeV2, AuthorityError> {
    let lineage = crate::v5_lineage::v5_lineage(receipt5);
    let (value, signature) = envelope_from_bytes(bytes)?;
    let canonical = bytes
        .strip_suffix(b"\n")
        .ok_or(AuthorityError::InvalidCanonicalReceipt)?;
    if <[u8; 32]>::from(Sha256::digest(canonical)) != expected_sha256 {
        return Err(AuthorityError::InvalidReceiptDigest);
    }
    validate(&value)?;
    if value.repository_id != "gocode"
        || value.receipt_sha256 != lineage.receipt_sha256
        || value.trust_config_sha256 != lineage.bindings.trust_config_sha256()
        || value.trust_generation != lineage.bindings.trust_generation()
    {
        return Err(AuthorityError::InvalidEvidenceEnvelope);
    }
    let payload = canonical_stage_payload(&value.payload)
        .map_err(|_| AuthorityError::InvalidEvidenceEnvelope)?;
    if <[u8; 32]>::from(Sha256::digest(&payload)) != value.payload_sha256 {
        return Err(AuthorityError::InvalidEvidenceEnvelope);
    }
    let pin = crate::v4_trust_schema_digests()?
        .into_iter()
        .find(|pin| pin.schema_id == value.payload_schema_id)
        .ok_or(AuthorityError::InvalidEvidenceEnvelope)?;
    if pin.schema_sha256 != value.payload_schema_sha256 {
        return Err(AuthorityError::InvalidEvidenceEnvelope);
    }
    let delegation = lineage
        .evidence_delegations
        .iter()
        .find(|item| item.role == value.issuer_role && item.scope == value.issuer_scope)
        .ok_or(AuthorityError::InvalidDelegation)?;
    if value.issuer_key_id == hex(&crate::key_id(&lineage.root_public_key))
        || value.issuer_principal_id != delegation.principal_id
        || value.issuer_controlling_account_id != delegation.controlling_account_id
        || value.issuer_lane_id != delegation.lane_id
        || value.issuer_key_id != delegation.key_id
        || value.issuer_key_epoch != delegation.key_epoch
        || value.signature_profile_id != delegation.signature_profile_id
        || value.revocation_epoch != delegation.revocation_epoch
        || !delegation
            .allowed_payload_schema_ids
            .contains(&value.payload_schema_id)
        || !within_delegation_window(&value, delegation)
    {
        return Err(AuthorityError::InvalidDelegation);
    }
    VerifyingKey::from_bytes(&delegation.public_key)
        .map_err(|_| AuthorityError::InvalidEvidenceEnvelope)?
        .verify_strict(
            &framed_transcript(DOMAIN_V2, &canonical_unsigned_evidence_envelope_v2(&value)?)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?;
    let scope = V5AdmissionScope {
        envelope_sha256: expected_sha256,
        receipt_sha256: value.receipt_sha256,
        trust_config_sha256: value.trust_config_sha256.clone(),
        trust_generation: value.trust_generation,
        issuer_role: value.issuer_role.clone(),
        issuer_scope: value.issuer_scope.clone(),
        issuer_principal_id: value.issuer_principal_id.clone(),
        issuer_controlling_account_id: value.issuer_controlling_account_id.clone(),
        issuer_lane_id: value.issuer_lane_id.clone(),
        issuer_key_id: value.issuer_key_id.clone(),
        issuer_key_epoch: value.issuer_key_epoch,
        issuer_signature_profile_id: value.signature_profile_id.clone(),
        payload_sha256: value.payload_sha256,
        payload_schema_id: value.payload_schema_id.clone(),
        payload_schema_sha256: value.payload_schema_sha256,
        issued_at: value.issued_at.clone(),
        revocation_epoch: value.revocation_epoch,
        not_before: value.not_before.clone(),
        expires_at: value.expires_at.clone(),
        nonce: value.authorization_nonce.clone(),
        root_identity: lineage.durable_root(),
        root_revocation_epoch: lineage.root_revocation_epoch,
        destination_allowlist_generation: lineage.bindings.destination_allowlist_generation(),
        role_scope_floors: lineage.role_floors(),
    };
    Ok(PrevalidatedEvidenceEnvelopeV2 {
        envelope_sha256: expected_sha256,
        receipt_sha256: value.receipt_sha256,
        payload_sha256: value.payload_sha256,
        payload_schema_id: value.payload_schema_id,
        payload,
        issuer: delegation.clone(),
        validity: EnvelopeValidityV2 {
            issued_at: value.issued_at,
            not_before: value.not_before,
            expires_at: value.expires_at,
            revocation_epoch: value.revocation_epoch,
            authorization_nonce: value.authorization_nonce,
            trust_generation: value.trust_generation,
        },
        scope,
    })
}

/// Serialize unsigned evidence-envelope `/2` fields as sorted canonical bytes.
/// These bytes (without any final LF) are the detached-signature transcript
/// preimage and the LF-excluded digest input.
///
/// # Errors
/// Returns an error only when JSON serialization fails.
pub fn canonical_unsigned_evidence_envelope_v2(
    value: &EvidenceAuthorityEnvelopeV2,
) -> Result<Vec<u8>, AuthorityError> {
    let mut root = BTreeMap::new();
    root.insert(
        "authorization_nonce",
        Value::String(value.authorization_nonce.clone()),
    );
    root.insert("expires_at", Value::String(value.expires_at.clone()));
    root.insert("issued_at", Value::String(value.issued_at.clone()));
    root.insert(
        "issuer_controlling_account_id",
        Value::String(value.issuer_controlling_account_id.clone()),
    );
    root.insert(
        "issuer_key_epoch",
        Value::Number(value.issuer_key_epoch.into()),
    );
    root.insert("issuer_key_id", Value::String(value.issuer_key_id.clone()));
    root.insert(
        "issuer_lane_id",
        Value::String(value.issuer_lane_id.clone()),
    );
    root.insert(
        "issuer_principal_id",
        Value::String(value.issuer_principal_id.clone()),
    );
    root.insert("issuer_role", Value::String(value.issuer_role.clone()));
    root.insert("issuer_scope", Value::String(value.issuer_scope.clone()));
    root.insert("not_before", Value::String(value.not_before.clone()));
    root.insert("payload", value.payload.clone());
    root.insert(
        "payload_schema_id",
        Value::String(value.payload_schema_id.clone()),
    );
    root.insert(
        "payload_schema_sha256",
        Value::String(hex(&value.payload_schema_sha256)),
    );
    root.insert("payload_sha256", Value::String(hex(&value.payload_sha256)));
    root.insert("receipt_sha256", Value::String(hex(&value.receipt_sha256)));
    root.insert("repository_id", Value::String(value.repository_id.clone()));
    root.insert(
        "revocation_epoch",
        Value::Number(value.revocation_epoch.into()),
    );
    root.insert(
        "schema_version",
        Value::String(value.schema_version.clone()),
    );
    root.insert(
        "signature_profile_id",
        Value::String(value.signature_profile_id.clone()),
    );
    root.insert(
        "trust_config_sha256",
        Value::String(value.trust_config_sha256.clone()),
    );
    root.insert(
        "trust_generation",
        Value::Number(value.trust_generation.into()),
    );
    serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)
}

/// Serialize checked-in evidence-envelope `/2` bytes including detached signature and one LF.
///
/// # Errors
/// Returns an error only when JSON serialization fails.
pub fn canonical_checked_in_evidence_envelope_v2(
    value: &EvidenceAuthorityEnvelopeV2,
    signature: &[u8; 64],
) -> Result<Vec<u8>, AuthorityError> {
    let mut root: BTreeMap<String, Value> =
        serde_json::from_slice(&canonical_unsigned_evidence_envelope_v2(value)?)
            .map_err(|_| AuthorityError::Serialization)?;
    root.insert(
        "signature".into(),
        Value::String(URL_SAFE_NO_PAD.encode(signature)),
    );
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate(value: &EvidenceAuthorityEnvelopeV2) -> Result<(), AuthorityError> {
    if !safe_id(&value.issuer_scope)
        || !hex_digest(&value.issuer_key_id)
        || !safe_id(&value.authorization_nonce)
        || value.issuer_key_epoch == 0
        || value.revocation_epoch == 0
        || !ordered(&value.issued_at, &value.not_before, &value.expires_at)
    {
        return Err(AuthorityError::InvalidEvidenceEnvelope);
    }
    Ok(())
}

#[allow(clippy::suspicious_operation_groupings)]
fn within_delegation_window(
    value: &EvidenceAuthorityEnvelopeV2,
    delegation: &crate::DelegationV2,
) -> bool {
    (value.issued_at >= delegation.not_before)
        && (value.not_before >= delegation.not_before)
        && (value.expires_at <= delegation.expires_at)
}

fn ordered(first: &str, second: &str, third: &str) -> bool {
    valid_timestamp(first)
        && valid_timestamp(second)
        && valid_timestamp(third)
        && first < second
        && second < third
}

fn envelope_from_bytes(
    bytes: &[u8],
) -> Result<(EvidenceAuthorityEnvelopeV2, [u8; 64]), AuthorityError> {
    let mut value = crate::strict_json::parse(bytes)?;
    if value
        .as_object()
        .and_then(|object| object.get("schema_version"))
        .and_then(Value::as_str)
        != Some(EVIDENCE_ENVELOPE_SCHEMA_V2)
    {
        return Err(AuthorityError::AuthorityVersionSuperseded);
    }
    let object = value
        .as_object_mut()
        .ok_or(AuthorityError::InvalidEvidenceEnvelope)?;
    let signature = signature(object.remove("signature"))?;
    for name in ["receipt_sha256", "payload_schema_sha256", "payload_sha256"] {
        hex_array(object, name)?;
    }
    let envelope = serde_json::from_value::<EvidenceAuthorityEnvelopeV2>(value)
        .map_err(|_| AuthorityError::InvalidEvidenceEnvelope)?;
    if canonical_checked_in_evidence_envelope_v2(&envelope, &signature)? != bytes {
        return Err(AuthorityError::InvalidCanonicalReceipt);
    }
    Ok((envelope, signature))
}
