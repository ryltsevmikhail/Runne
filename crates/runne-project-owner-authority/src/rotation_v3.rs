//! Version-3 trust evolution rotation from the exact V2 predecessor.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

use crate::{
    AuthorityError, ProjectOwnerTrustConfigV2, ProjectOwnerTrustConfigV3, SchemaDigest,
    VerifiedTrustConfigV2, VerifiedTrustConfigV3, framed_transcript, key_id,
    trust_canonical::hex,
    trust_v2::verify_v2_config,
    trust_v3::{CONFIG_SCHEMA_V3, POP_DOMAIN_V3, canonical_config_v3, v3_trust_schema_digests},
};

const ROTATION_SCHEMA_V3: &str = "gocode.project-owner.key-rotation/3";
const OLD_DOMAIN_V3: &[u8] = b"gocode.project-owner.rotation-old-authorization/3";

/// V2-to-V3 rotation binding exactly one predecessor and one successor key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRotationV3 {
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

impl KeyRotationV3 {
    /// Parse only exact canonical V3 rotation JSON.
    ///
    /// # Errors
    /// Returns an error for malformed or noncanonical bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorityError> {
        crate::rotation_v3_wire::parse(bytes)
    }

    /// Return exact canonical V3 rotation JSON including one final LF.
    ///
    /// # Errors
    /// Returns an error for noncanonical schema pins.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, AuthorityError> {
        canonical_rotation_v3(self, true)
    }
}

/// Verify the mandatory V2-to-V3 transition.
///
/// # Errors
/// Returns an error for a skipped epoch, wrong predecessor, key reuse, incomplete
/// pin union, or invalid old/new signatures.
pub fn verify_trust_upgrade_v2_to_v3(
    old: &VerifiedTrustConfigV2,
    rotation: &KeyRotationV3,
) -> Result<VerifiedTrustConfigV3, AuthorityError> {
    let old = old.config();
    verify_v2_config(old)?;
    if rotation.schema_version != ROTATION_SCHEMA_V3
        || rotation.repository_id != old.repository_id
        || rotation.role != old.role
        || rotation.old_trust_schema_version != old.schema_version
        || rotation.old_trust_config_sha256 != old.sha256()?
        || rotation.old_key_id != old.key_id
        || rotation.old_epoch != old.epoch
    {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    if rotation.new_trust_schema_version != CONFIG_SCHEMA_V3
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
    if rotation.new_schema_digests != v3_trust_schema_digests()? {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    let successor = successor(rotation, old.sha256()?);
    let new_key = VerifyingKey::from_bytes(&rotation.new_public_key)
        .map_err(|_| AuthorityError::InvalidRotationNewPop)?;
    new_key
        .verify_strict(
            &framed_transcript(POP_DOMAIN_V3, &canonical_config_v3(&successor, false)?)?,
            &Signature::from_bytes(&rotation.new_proof_of_possession),
        )
        .map_err(|_| AuthorityError::InvalidRotationNewPop)?;
    let old_key = VerifyingKey::from_bytes(&old.public_key)
        .map_err(|_| AuthorityError::InvalidRotationOldAuthorization)?;
    old_key
        .verify_strict(
            &rotation_v3_old_authorization_transcript(rotation)?,
            &Signature::from_bytes(&rotation.old_authorization),
        )
        .map_err(|_| AuthorityError::InvalidRotationOldAuthorization)?;
    Ok(crate::trust_v3::verified_v3(successor))
}

/// Canonical V3 rotation bytes, optionally omitting old-key authorization.
///
/// # Errors
/// Returns an error for noncanonical schema pins.
pub fn canonical_rotation_v3(
    rotation: &KeyRotationV3,
    include_old_authorization: bool,
) -> Result<Vec<u8>, AuthorityError> {
    if !crate::trust_v2::valid_pins(&rotation.new_schema_digests) {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    let pins = rotation.new_schema_digests.iter().map(pin_value).collect();
    let mut root = BTreeMap::from([
        ("new_epoch", Value::Number(rotation.new_epoch.into())),
        ("new_key_id", Value::String(hex(&rotation.new_key_id))),
        (
            "new_proof_of_possession",
            Value::String(URL_SAFE_NO_PAD.encode(rotation.new_proof_of_possession)),
        ),
        (
            "new_public_key",
            Value::String(URL_SAFE_NO_PAD.encode(rotation.new_public_key)),
        ),
        ("new_schema_digests", Value::Array(pins)),
        (
            "new_trust_schema_version",
            Value::String(rotation.new_trust_schema_version.clone()),
        ),
        ("old_epoch", Value::Number(rotation.old_epoch.into())),
        ("old_key_id", Value::String(hex(&rotation.old_key_id))),
        (
            "old_trust_config_sha256",
            Value::String(hex(&rotation.old_trust_config_sha256)),
        ),
        (
            "old_trust_schema_version",
            Value::String(rotation.old_trust_schema_version.clone()),
        ),
        (
            "repository_id",
            Value::String(rotation.repository_id.clone()),
        ),
        ("role", Value::String(rotation.role.clone())),
        (
            "schema_version",
            Value::String(rotation.schema_version.clone()),
        ),
    ]);
    if include_old_authorization {
        root.insert(
            "old_authorization",
            Value::String(URL_SAFE_NO_PAD.encode(rotation.old_authorization)),
        );
    }
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// New-key proof transcript for an exact V2 predecessor.
///
/// # Errors
/// Returns an error when the rotation does not bind that exact predecessor.
pub fn rotation_v3_new_pop_transcript(
    old: &ProjectOwnerTrustConfigV2,
    rotation: &KeyRotationV3,
) -> Result<Vec<u8>, AuthorityError> {
    if rotation.old_trust_config_sha256 != old.sha256()? {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    framed_transcript(
        POP_DOMAIN_V3,
        &canonical_config_v3(&successor(rotation, old.sha256()?), false)?,
    )
}

/// Exact old-key V3 authorization transcript.
///
/// # Errors
/// Returns an error for noncanonical schema pins.
pub fn rotation_v3_old_authorization_transcript(
    rotation: &KeyRotationV3,
) -> Result<Vec<u8>, AuthorityError> {
    framed_transcript(OLD_DOMAIN_V3, &canonical_rotation_v3(rotation, false)?)
}

fn successor(rotation: &KeyRotationV3, predecessor: [u8; 32]) -> ProjectOwnerTrustConfigV3 {
    ProjectOwnerTrustConfigV3 {
        schema_version: rotation.new_trust_schema_version.clone(),
        repository_id: rotation.repository_id.clone(),
        role: rotation.role.clone(),
        epoch: rotation.new_epoch,
        key_id: rotation.new_key_id,
        public_key: rotation.new_public_key,
        schema_digests: rotation.new_schema_digests.clone(),
        proof_of_possession: rotation.new_proof_of_possession,
        predecessor,
        predecessor_schema_version: "gocode.project-owner.trust-config/2".into(),
    }
}

fn pin_value(pin: &SchemaDigest) -> Value {
    Value::Object(
        BTreeMap::from([
            ("schema_id".into(), Value::String(pin.schema_id.clone())),
            (
                "schema_sha256".into(),
                Value::String(hex(&pin.schema_sha256)),
            ),
        ])
        .into_iter()
        .collect(),
    )
}
