//! Canonical publication-effect intent wire shared by Rust and JSON Schema.
#![allow(clippy::missing_errors_doc, dead_code, clippy::redundant_pub_crate)]

use serde::{Deserialize, Serialize};

use crate::Digest;
use crate::publication_effect_types::{PublicationEffectError, PublicationEffectScope};

pub(crate) const SCHEMA: &str = "gocode.release.publication-effect-intent/1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Exact JSON Schema identity property names.
pub(crate) struct ExecutorIdentityWire {
    pub principal_id: String,
    pub account_id: String,
    pub lane_id: String,
    pub key_id: String,
    pub signature_profile_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationEffectIntentWire {
    pub schema_version: String,
    pub authority_instance_sha256: String,
    pub promotion: String,
    pub candidate_sha256: String,
    pub rc3_authorization_sha256: String,
    pub publication_manifest_sha256: String,
    pub final_review_sha256: String,
    pub allowlist_sha256: String,
    pub allowlist_generation: u64,
    pub destination: String,
    pub channel: String,
    pub effect_kind: String,
    pub effect_scope_sha256: String,
    pub executor: ExecutorIdentityWire,
    pub executable_sha256: String,
    pub workflow_sha256: String,
    pub idempotency_namespace: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub generation: u64,
}

impl From<&PublicationEffectScope> for PublicationEffectIntentWire {
    fn from(scope: &PublicationEffectScope) -> Self {
        let [
            principal_id,
            account_id,
            lane_id,
            key_id,
            signature_profile_id,
        ] = scope.executor.clone();
        Self {
            schema_version: SCHEMA.into(),
            authority_instance_sha256: scope.authority_instance.to_hex(),
            promotion: scope.promotion.clone(),
            candidate_sha256: scope.candidate_digest.to_hex(),
            rc3_authorization_sha256: scope.rc3_authorization_digest.to_hex(),
            publication_manifest_sha256: scope.manifest_digest.to_hex(),
            final_review_sha256: scope.final_review_digest.to_hex(),
            allowlist_sha256: scope.allowlist_digest.to_hex(),
            allowlist_generation: scope.allowlist_generation,
            destination: scope.destination.clone(),
            channel: scope.channel.clone(),
            effect_kind: scope.effect_kind.clone(),
            effect_scope_sha256: scope.effect_scope_digest.to_hex(),
            executor: ExecutorIdentityWire {
                principal_id,
                account_id,
                lane_id,
                key_id,
                signature_profile_id,
            },
            executable_sha256: scope.executable_digest.to_hex(),
            workflow_sha256: scope.workflow_digest.to_hex(),
            idempotency_namespace: scope.idempotency_namespace.clone(),
            valid_from: scope.valid_from,
            expires_at: scope.expires_at,
            revocation_epoch: scope.revocation_epoch,
            generation: scope.generation,
        }
    }
}

pub(crate) fn encode_intent(
    scope: &PublicationEffectScope,
) -> Result<Vec<u8>, PublicationEffectError> {
    if !scope.is_well_formed() {
        return Err(PublicationEffectError::InvalidAuthorization);
    }
    let value = serde_json::to_value(PublicationEffectIntentWire::from(scope))
        .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
    let mut bytes = serde_json::to_vec(&crate::wire::sorted_value(value))
        .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn decode_intent(
    value: PublicationEffectIntentWire,
) -> Result<PublicationEffectScope, PublicationEffectError> {
    if value.schema_version != SCHEMA {
        return Err(PublicationEffectError::DurableStateUnavailable);
    }
    let scope = PublicationEffectScope {
        authority_instance: digest(&value.authority_instance_sha256)?,
        promotion: value.promotion,
        candidate_digest: digest(&value.candidate_sha256)?,
        rc3_authorization_digest: digest(&value.rc3_authorization_sha256)?,
        manifest_digest: digest(&value.publication_manifest_sha256)?,
        final_review_digest: digest(&value.final_review_sha256)?,
        allowlist_digest: digest(&value.allowlist_sha256)?,
        allowlist_generation: value.allowlist_generation,
        destination: value.destination,
        channel: value.channel,
        effect_kind: value.effect_kind,
        effect_scope_digest: digest(&value.effect_scope_sha256)?,
        executor: [
            value.executor.principal_id,
            value.executor.account_id,
            value.executor.lane_id,
            value.executor.key_id,
            value.executor.signature_profile_id,
        ],
        executable_digest: digest(&value.executable_sha256)?,
        workflow_digest: digest(&value.workflow_sha256)?,
        idempotency_namespace: value.idempotency_namespace,
        valid_from: value.valid_from,
        expires_at: value.expires_at,
        revocation_epoch: value.revocation_epoch,
        generation: value.generation,
    };
    scope
        .is_well_formed()
        .then_some(scope)
        .ok_or(PublicationEffectError::DurableStateUnavailable)
}

pub(crate) fn digest(value: &str) -> Result<Digest, PublicationEffectError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|x| x.is_ascii_hexdigit() && !x.is_ascii_uppercase())
    {
        return Err(PublicationEffectError::DurableStateUnavailable);
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = u8::from_str_radix(
            std::str::from_utf8(pair)
                .map_err(|_| PublicationEffectError::DurableStateUnavailable)?,
            16,
        )
        .map_err(|_| PublicationEffectError::DurableStateUnavailable)?;
    }
    Ok(Digest::fixture(output))
}
