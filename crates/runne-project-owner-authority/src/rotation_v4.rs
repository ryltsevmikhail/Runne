//! Version-4 rotation: the only path from verified V3 trust to active V4 trust.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

use crate::{
    AuthorityError, ProjectOwnerTrustConfigV3, ProjectOwnerTrustConfigV4, SchemaDigest,
    VerifiedTrustConfigV3, VerifiedTrustConfigV4, framed_transcript, key_id,
    trust_canonical::hex,
    trust_v3::verify_v3_config,
    trust_v4::{CONFIG_SCHEMA_V4, POP_DOMAIN_V4, canonical_config_v4, v4_trust_schema_digests},
};

const ROTATION_SCHEMA_V4: &str = "gocode.project-owner.key-rotation/4";
const OLD_DOMAIN_V4: &[u8] = b"gocode.project-owner.rotation-old-authorization/4";

/// Signed V3-to-V4 root-key rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRotationV4 {
    pub schema_version: String,
    pub repository_id: String,
    pub role: String,
    pub old_trust_schema_version: String,
    pub old_trust_config_sha256: [u8; 32],
    pub old_key_id: [u8; 32],
    pub old_epoch: u64,
    pub new_trust_schema_version: String,
    pub new_key_id: [u8; 32],
    pub new_public_key: [u8; 32],
    pub new_epoch: u64,
    pub new_schema_digests: Vec<SchemaDigest>,
    pub old_authorization: [u8; 64],
    pub new_proof_of_possession: [u8; 64],
}

/// Verify an exact authenticated V3 lineage and mint opaque V4 trust.
///
/// # Errors
/// Returns an error for a wrong lineage, key, signature, epoch, or pin union.
pub fn verify_trust_upgrade_v3_to_v4(
    old: &VerifiedTrustConfigV3,
    rotation: &KeyRotationV4,
) -> Result<VerifiedTrustConfigV4, AuthorityError> {
    let old = old.config();
    verify_v3_config(old)?;
    if rotation.schema_version != ROTATION_SCHEMA_V4
        || rotation.repository_id != old.repository_id
        || rotation.role != old.role
        || rotation.old_trust_schema_version != old.schema_version
        || rotation.old_trust_config_sha256 != old.sha256()?
        || rotation.old_key_id != old.key_id
        || rotation.old_epoch != old.epoch
    {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    if rotation.new_trust_schema_version != CONFIG_SCHEMA_V4
        || rotation.new_epoch
            != old
                .epoch
                .checked_add(1)
                .ok_or(AuthorityError::InvalidRotationEpoch)?
    {
        return Err(AuthorityError::InvalidRotationEpoch);
    }
    if rotation.new_key_id != key_id(&rotation.new_public_key) || rotation.new_key_id == old.key_id
    {
        return Err(AuthorityError::InvalidRotationKey);
    }
    if rotation.new_schema_digests != v4_trust_schema_digests()? {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    let successor = successor(rotation, old.sha256()?);
    VerifyingKey::from_bytes(&rotation.new_public_key)
        .map_err(|_| AuthorityError::InvalidRotationNewPop)?
        .verify_strict(
            &framed_transcript(POP_DOMAIN_V4, &canonical_config_v4(&successor, false)?)?,
            &Signature::from_bytes(&rotation.new_proof_of_possession),
        )
        .map_err(|_| AuthorityError::InvalidRotationNewPop)?;
    VerifyingKey::from_bytes(&old.public_key)
        .map_err(|_| AuthorityError::InvalidRotationOldAuthorization)?
        .verify_strict(
            &rotation_v4_old_authorization_transcript(rotation)?,
            &Signature::from_bytes(&rotation.old_authorization),
        )
        .map_err(|_| AuthorityError::InvalidRotationOldAuthorization)?;
    Ok(crate::trust_v4::verified_v4(successor))
}

/// Canonical V4 rotation bytes, optionally omitting the old-key authorization.
///
/// # Errors
/// Returns an error when schema pins are not canonical.
pub fn canonical_rotation_v4(
    value: &KeyRotationV4,
    include_old_authorization: bool,
) -> Result<Vec<u8>, AuthorityError> {
    if !crate::trust_v2::valid_pins(&value.new_schema_digests) {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    let mut root = BTreeMap::from([
        ("new_epoch", Value::Number(value.new_epoch.into())),
        ("new_key_id", Value::String(hex(&value.new_key_id))),
        (
            "new_proof_of_possession",
            Value::String(URL_SAFE_NO_PAD.encode(value.new_proof_of_possession)),
        ),
        (
            "new_public_key",
            Value::String(URL_SAFE_NO_PAD.encode(value.new_public_key)),
        ),
        (
            "new_schema_digests",
            Value::Array(value.new_schema_digests.iter().map(pin).collect()),
        ),
        (
            "new_trust_schema_version",
            Value::String(value.new_trust_schema_version.clone()),
        ),
        ("old_epoch", Value::Number(value.old_epoch.into())),
        ("old_key_id", Value::String(hex(&value.old_key_id))),
        (
            "old_trust_config_sha256",
            Value::String(hex(&value.old_trust_config_sha256)),
        ),
        (
            "old_trust_schema_version",
            Value::String(value.old_trust_schema_version.clone()),
        ),
        ("repository_id", Value::String(value.repository_id.clone())),
        ("role", Value::String(value.role.clone())),
        (
            "schema_version",
            Value::String(value.schema_version.clone()),
        ),
    ]);
    if include_old_authorization {
        root.insert(
            "old_authorization",
            Value::String(URL_SAFE_NO_PAD.encode(value.old_authorization)),
        );
    }
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Construct the V4 new-key proof transcript bound to one exact V3 predecessor.
///
/// # Errors
/// Returns an error when the predecessor digest or schema pins are invalid.
pub fn rotation_v4_new_pop_transcript(
    old: &ProjectOwnerTrustConfigV3,
    value: &KeyRotationV4,
) -> Result<Vec<u8>, AuthorityError> {
    if value.old_trust_config_sha256 != old.sha256()? {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    framed_transcript(
        POP_DOMAIN_V4,
        &canonical_config_v4(&successor(value, old.sha256()?), false)?,
    )
}

/// Construct the exact V4 old-key authorization transcript.
///
/// # Errors
/// Returns an error when schema pins are not canonical.
pub fn rotation_v4_old_authorization_transcript(
    value: &KeyRotationV4,
) -> Result<Vec<u8>, AuthorityError> {
    framed_transcript(OLD_DOMAIN_V4, &canonical_rotation_v4(value, false)?)
}

fn successor(value: &KeyRotationV4, predecessor: [u8; 32]) -> ProjectOwnerTrustConfigV4 {
    ProjectOwnerTrustConfigV4 {
        schema_version: value.new_trust_schema_version.clone(),
        repository_id: value.repository_id.clone(),
        role: value.role.clone(),
        epoch: value.new_epoch,
        key_id: value.new_key_id,
        public_key: value.new_public_key,
        schema_digests: value.new_schema_digests.clone(),
        proof_of_possession: value.new_proof_of_possession,
        predecessor,
        predecessor_schema_version: "gocode.project-owner.trust-config/3".into(),
    }
}
fn pin(value: &SchemaDigest) -> Value {
    Value::Object(
        BTreeMap::from([
            ("schema_id".into(), Value::String(value.schema_id.clone())),
            (
                "schema_sha256".into(),
                Value::String(hex(&value.schema_sha256)),
            ),
        ])
        .into_iter()
        .collect(),
    )
}
