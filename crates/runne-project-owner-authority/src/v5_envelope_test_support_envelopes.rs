#![allow(clippy::cast_possible_truncation)]

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use crate::{V5_EVIDENCE_ROLE_SCOPES, V5_TRANSITION_ROLES, VerifiedPromotionBootstrapV5};

pub fn transition_key(index: usize) -> SigningKey {
    SigningKey::from_bytes(&[10 + index as u8; 32])
}
pub fn evidence_key(index: usize) -> SigningKey {
    SigningKey::from_bytes(&[13 + index as u8; 32])
}

pub fn stage_envelope(
    receipt5: &VerifiedPromotionBootstrapV5,
    role: &str,
) -> (crate::StageAuthorityEnvelopeV2, SigningKey) {
    let delegation = receipt5
        .transition_delegation(role)
        .expect("fixture transition role")
        .clone();
    let key = transition_key(
        V5_TRANSITION_ROLES
            .iter()
            .position(|item| *item == role)
            .expect("closed transition role"),
    );
    let payload = serde_json::json!({"schema_version": delegation.allowed_payload_schema_ids[0]});
    (
        crate::StageAuthorityEnvelopeV2 {
            schema_version: crate::STAGE_ENVELOPE_SCHEMA_V2.into(),
            repository_id: "runne".into(),
            receipt_sha256: receipt5.receipt_sha256(),
            trust_config_sha256: receipt5.bindings().trust_config_sha256().into(),
            trust_generation: receipt5.bindings().trust_generation(),
            issuer_role: delegation.role.clone(),
            issuer_principal_id: delegation.principal_id.clone(),
            issuer_controlling_account_id: delegation.controlling_account_id.clone(),
            issuer_lane_id: delegation.lane_id.clone(),
            issuer_key_id: delegation.key_id.clone(),
            issuer_key_epoch: delegation.key_epoch,
            signature_profile_id: delegation.signature_profile_id.clone(),
            payload_schema_id: delegation.allowed_payload_schema_ids[0].clone(),
            payload_schema_sha256: schema_pin(&delegation.allowed_payload_schema_ids[0]),
            payload_sha256: Sha256::digest(crate::canonical_stage_payload(&payload).unwrap())
                .into(),
            payload,
            issued_at: "2026-01-01T00:00:02Z".into(),
            not_before: "2026-01-01T00:00:03Z".into(),
            expires_at: "2026-01-01T00:00:04Z".into(),
            revocation_epoch: delegation.revocation_epoch,
            authorization_nonce: "nonce-stage-1".into(),
        },
        key,
    )
}

pub fn evidence_envelope(
    receipt5: &VerifiedPromotionBootstrapV5,
    role: &str,
    scope: &str,
) -> (crate::EvidenceAuthorityEnvelopeV2, SigningKey) {
    let delegation = receipt5
        .evidence_delegation(role, scope)
        .expect("fixture evidence role/scope")
        .clone();
    let key = evidence_key(
        V5_EVIDENCE_ROLE_SCOPES
            .iter()
            .position(|item| item.0 == role && item.1 == scope)
            .expect("closed evidence scope"),
    );
    let payload = serde_json::json!({"schema_version": delegation.allowed_payload_schema_ids[0]});
    (
        crate::EvidenceAuthorityEnvelopeV2 {
            schema_version: crate::EVIDENCE_ENVELOPE_SCHEMA_V2.into(),
            repository_id: "runne".into(),
            receipt_sha256: receipt5.receipt_sha256(),
            trust_config_sha256: receipt5.bindings().trust_config_sha256().into(),
            trust_generation: receipt5.bindings().trust_generation(),
            issuer_role: delegation.role.clone(),
            issuer_scope: delegation.scope.clone(),
            issuer_principal_id: delegation.principal_id.clone(),
            issuer_controlling_account_id: delegation.controlling_account_id.clone(),
            issuer_lane_id: delegation.lane_id.clone(),
            issuer_key_id: delegation.key_id.clone(),
            issuer_key_epoch: delegation.key_epoch,
            signature_profile_id: delegation.signature_profile_id.clone(),
            payload_schema_id: delegation.allowed_payload_schema_ids[0].clone(),
            payload_schema_sha256: schema_pin(&delegation.allowed_payload_schema_ids[0]),
            payload_sha256: Sha256::digest(crate::canonical_stage_payload(&payload).unwrap())
                .into(),
            payload,
            issued_at: "2026-01-01T00:00:02Z".into(),
            not_before: "2026-01-01T00:00:03Z".into(),
            expires_at: "2026-01-01T00:00:04Z".into(),
            revocation_epoch: delegation.revocation_epoch,
            authorization_nonce: "nonce-evidence-1".into(),
        },
        key,
    )
}

fn schema_pin(schema_id: &str) -> [u8; 32] {
    crate::v4_trust_schema_digests()
        .unwrap()
        .into_iter()
        .find(|pin| pin.schema_id == schema_id)
        .expect("closed schema id has a test pin")
        .schema_sha256
}

pub fn signed_stage_v2(envelope: &crate::StageAuthorityEnvelopeV2, key: &SigningKey) -> Vec<u8> {
    let signature = key
        .sign(
            &crate::framed_transcript(
                b"runne.release.post-rc0-stage-envelope/2",
                &crate::canonical_unsigned_stage_envelope_v2(envelope).unwrap(),
            )
            .unwrap(),
        )
        .to_bytes();
    crate::canonical_checked_in_stage_envelope_v2(envelope, &signature).unwrap()
}
pub fn signed_evidence_v2(
    envelope: &crate::EvidenceAuthorityEnvelopeV2,
    key: &SigningKey,
) -> Vec<u8> {
    let signature = key
        .sign(
            &crate::framed_transcript(
                b"runne.release.post-rc0-evidence-envelope/2",
                &crate::canonical_unsigned_evidence_envelope_v2(envelope).unwrap(),
            )
            .unwrap(),
        )
        .to_bytes();
    crate::canonical_checked_in_evidence_envelope_v2(envelope, &signature).unwrap()
}
