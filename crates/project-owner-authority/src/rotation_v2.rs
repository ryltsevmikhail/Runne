//! Version-2 trust evolution rotations.
use crate::{
    AuthorityError, ProjectOwnerTrustConfigV1, ProjectOwnerTrustConfigV2, SchemaDigest,
    VerifiedTrustConfigV2, framed_transcript, key_id,
    trust::verify_genesis,
    trust_canonical::hex,
    trust_v2::{CONFIG_SCHEMA_V2, POP_DOMAIN_V2, canonical_config_v2, v2_trust_schema_digests},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use std::collections::BTreeMap;
const ROTATION_SCHEMA_V2: &str = "gocode.project-owner.key-rotation/2";
const OLD_DOMAIN_V2: &[u8] = b"gocode.project-owner.rotation-old-authorization/2";
/// A rotation that binds an exact old trust configuration to an exact V2 successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRotationV2 {
    /// Fixed rotation schema identifier.
    pub schema_version: String,
    /// Repository governed by the rotation.
    pub repository_id: String,
    /// Fixed project-owner role.
    pub role: String,
    /// Schema version of the old trust configuration.
    pub old_trust_schema_version: String,
    /// SHA-256 of the exact old trust configuration.
    pub old_trust_config_sha256: [u8; 32],
    /// Active predecessor key identifier.
    pub old_key_id: [u8; 32],
    /// Active predecessor epoch.
    pub old_epoch: u64,
    /// Fixed V2 successor trust schema identifier.
    pub new_trust_schema_version: String,
    /// New public-key identifier.
    pub new_key_id: [u8; 32],
    /// New Ed25519 public key.
    pub new_public_key: [u8; 32],
    /// Exact successor epoch.
    pub new_epoch: u64,
    /// Exact successor schema pins.
    pub new_schema_digests: Vec<SchemaDigest>,
    /// Old-key authorization over this exact rotation including the new proof.
    pub old_authorization: [u8; 64],
    /// New-key proof over the complete successor configuration without this proof.
    pub new_proof_of_possession: [u8; 64],
}
impl KeyRotationV2 {
    /// Parse only exact canonical V2 rotation JSON.
    ///
    /// # Errors
    /// Returns a fail-closed error for malformed or noncanonical input.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorityError> {
        crate::rotation_v2_wire::parse(bytes)
    }

    /// Return exact canonical V2 rotation JSON, including one final LF.
    ///
    /// # Errors
    /// Returns an error when the schema pins are noncanonical.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, AuthorityError> {
        canonical_rotation_v2(self, true)
    }
}

/// Verify the mandatory V1-genesis to V2 transition.
///
/// # Errors
/// Rejects V1 successors, same-key changes, altered pins, and either invalid signature.
pub fn verify_trust_upgrade_v1_to_v2(
    old: &ProjectOwnerTrustConfigV1,
    rotation: &KeyRotationV2,
) -> Result<VerifiedTrustConfigV2, AuthorityError> {
    verify_genesis(old)?;
    verify_transition(
        &old.schema_version,
        old.sha256()?,
        old.key_id,
        old.public_key,
        old.epoch,
        &old.repository_id,
        &old.role,
        rotation,
    )
}

/// Verify a V2-to-V2 continuity rotation preserving the exact V2 pin set.
///
/// # Errors
/// Rejects same-key, same-epoch, predecessor, pin, and signature mismatches.
pub fn verify_rotation_v2(
    old: &VerifiedTrustConfigV2,
    rotation: &KeyRotationV2,
) -> Result<VerifiedTrustConfigV2, AuthorityError> {
    let old = old.config();
    verify_transition(
        &old.schema_version,
        old.sha256()?,
        old.key_id,
        old.public_key,
        old.epoch,
        &old.repository_id,
        &old.role,
        rotation,
    )
}

#[expect(clippy::too_many_arguments, reason = "predecessor binding is explicit")]
fn verify_transition(
    old_schema: &str,
    old_digest: [u8; 32],
    old_key_id: [u8; 32],
    old_public_key: [u8; 32],
    old_epoch: u64,
    repository: &str,
    role: &str,
    rotation: &KeyRotationV2,
) -> Result<VerifiedTrustConfigV2, AuthorityError> {
    if rotation.schema_version != ROTATION_SCHEMA_V2
        || rotation.repository_id != repository
        || rotation.role != role
        || rotation.old_trust_schema_version != old_schema
        || rotation.old_trust_config_sha256 != old_digest
        || rotation.old_key_id != old_key_id
        || rotation.old_epoch != old_epoch
    {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    if rotation.new_trust_schema_version != CONFIG_SCHEMA_V2
        || rotation.new_epoch
            != old_epoch
                .checked_add(1)
                .ok_or(AuthorityError::InvalidRotationEpoch)?
    {
        return Err(AuthorityError::InvalidRotationEpoch);
    }
    if rotation.new_key_id != key_id(&rotation.new_public_key) || rotation.new_key_id == old_key_id
    {
        return Err(AuthorityError::InvalidRotationKey);
    }
    if rotation.new_schema_digests != v2_trust_schema_digests() {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    let successor = successor(rotation, old_digest, old_schema);
    let new_key = VerifyingKey::from_bytes(&rotation.new_public_key)
        .map_err(|_| AuthorityError::InvalidRotationNewPop)?;
    new_key
        .verify_strict(
            &rotation_v2_new_pop_transcript_from(&successor)?,
            &Signature::from_bytes(&rotation.new_proof_of_possession),
        )
        .map_err(|_| AuthorityError::InvalidRotationNewPop)?;
    let old_key = VerifyingKey::from_bytes(&old_public_key)
        .map_err(|_| AuthorityError::InvalidRotationOldAuthorization)?;
    old_key
        .verify_strict(
            &rotation_v2_old_authorization_transcript(rotation)?,
            &Signature::from_bytes(&rotation.old_authorization),
        )
        .map_err(|_| AuthorityError::InvalidRotationOldAuthorization)?;
    Ok(crate::trust_v2::verified_v2(successor))
}

/// Canonical V2 rotation bytes, optionally omitting the old-key authorization.
///
/// # Errors
/// Returns an error when successor pins differ from the reviewed union.
pub fn canonical_rotation_v2(
    rotation: &KeyRotationV2,
    include_old_authorization: bool,
) -> Result<Vec<u8>, AuthorityError> {
    if rotation.new_schema_digests != v2_trust_schema_digests() {
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

/// New-key V2 proof transcript for a supplied V1 predecessor.
///
/// # Errors
/// Returns an error when the rotation does not bind the exact predecessor.
pub fn rotation_v2_new_pop_transcript(
    old: &ProjectOwnerTrustConfigV1,
    rotation: &KeyRotationV2,
) -> Result<Vec<u8>, AuthorityError> {
    if rotation.old_trust_config_sha256 != old.sha256()? {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    rotation_v2_new_pop_transcript_from(&successor(rotation, old.sha256()?, &old.schema_version))
}

/// New-key V2 proof transcript for a V2 predecessor.
///
/// # Errors
/// Returns an error when the rotation does not bind the exact predecessor.
pub fn rotation_v2_successor_pop_transcript(
    old: &ProjectOwnerTrustConfigV2,
    rotation: &KeyRotationV2,
) -> Result<Vec<u8>, AuthorityError> {
    if rotation.old_trust_config_sha256 != old.sha256()? {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    rotation_v2_new_pop_transcript_from(&successor(rotation, old.sha256()?, &old.schema_version))
}

/// Exact old-key V2 authorization transcript.
///
/// # Errors
/// Returns an error when successor pins differ from the reviewed union.
pub fn rotation_v2_old_authorization_transcript(
    rotation: &KeyRotationV2,
) -> Result<Vec<u8>, AuthorityError> {
    framed_transcript(OLD_DOMAIN_V2, &canonical_rotation_v2(rotation, false)?)
}

fn rotation_v2_new_pop_transcript_from(
    successor: &ProjectOwnerTrustConfigV2,
) -> Result<Vec<u8>, AuthorityError> {
    framed_transcript(POP_DOMAIN_V2, &canonical_config_v2(successor, false)?)
}

fn successor(
    rotation: &KeyRotationV2,
    predecessor: [u8; 32],
    predecessor_schema_version: &str,
) -> ProjectOwnerTrustConfigV2 {
    ProjectOwnerTrustConfigV2 {
        schema_version: rotation.new_trust_schema_version.clone(),
        repository_id: rotation.repository_id.clone(),
        role: rotation.role.clone(),
        epoch: rotation.new_epoch,
        key_id: rotation.new_key_id,
        public_key: rotation.new_public_key,
        schema_digests: rotation.new_schema_digests.clone(),
        proof_of_possession: rotation.new_proof_of_possession,
        predecessor,
        predecessor_schema_version: predecessor_schema_version.into(),
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
