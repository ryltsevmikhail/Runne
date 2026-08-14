//! Verified single-key continuity rotations and explicit compromise reset signals.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

use crate::{
    AuthorityError, ProjectOwnerTrustConfigV1, TrustAnchorState, framed_transcript, key_id,
    trust::{verify_active_trust_config, verify_chain_anchor, verify_pinned_chain_member},
    trust_canonical::{canonical_config, hex},
};

const ROTATION_SCHEMA: &str = "gocode.project-owner.key-rotation/1";
const OLD_DOMAIN: &[u8] = b"gocode.project-owner.rotation-old-authorization/1";
const NEW_DOMAIN: &[u8] = b"gocode.project-owner.rotation-new-proof-of-possession/1";

/// Public proof that the active owner key authorized exactly one successor key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRotationV1 {
    /// Fixed rotation schema identifier.
    pub schema_version: String,
    /// Repository whose trust chain is advanced.
    pub repository_id: String,
    /// Fixed sole-authority role.
    pub role: String,
    /// SHA-256 of the exact canonical predecessor trust config.
    pub predecessor_config_sha256: [u8; 32],
    /// Active predecessor key identifier.
    pub old_key_id: [u8; 32],
    /// Active predecessor epoch.
    pub old_epoch: u64,
    /// Domain-separated identifier for `new_public_key`.
    pub new_key_id: [u8; 32],
    /// Pending successor public key, never a signing authority before verification.
    pub new_public_key: [u8; 32],
    /// Exact next key epoch.
    pub new_epoch: u64,
    /// Old-key authorization over the unsigned rotation core.
    pub old_authorization: [u8; 64],
    /// New-key proof of possession over the same unsigned rotation core.
    pub new_proof_of_possession: [u8; 64],
}

/// Explicit non-continuity recovery signal after a human compromise declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustResetRequired {
    /// Repository that must be manually re-bootstrapped with a new genesis.
    pub repository_id: String,
    /// Compromised active key identifier.
    pub compromised_key_id: [u8; 32],
    /// Compromised active epoch.
    pub compromised_epoch: u64,
}

/// Verify one exact predecessor-to-successor continuity transition.
///
/// # Errors
///
/// Returns a fail-closed error for every invalid binding, transcript, or signature.
pub fn verify_rotation(
    old: &ProjectOwnerTrustConfigV1,
    rotation: &KeyRotationV1,
) -> Result<ProjectOwnerTrustConfigV1, AuthorityError> {
    validate_binding(old, rotation)?;
    let new_key = VerifyingKey::from_bytes(&rotation.new_public_key)
        .map_err(|_| AuthorityError::InvalidRotationNewPop)?;
    new_key
        .verify_strict(
            &rotation_new_pop_transcript(old, rotation)?,
            &Signature::from_bytes(&rotation.new_proof_of_possession),
        )
        .map_err(|_| AuthorityError::InvalidRotationNewPop)?;
    let old_key = VerifyingKey::from_bytes(&old.public_key)
        .map_err(|_| AuthorityError::InvalidRotationOldAuthorization)?;
    old_key
        .verify_strict(
            &rotation_old_authorization_transcript(rotation)?,
            &Signature::from_bytes(&rotation.old_authorization),
        )
        .map_err(|_| AuthorityError::InvalidRotationOldAuthorization)?;
    Ok(ProjectOwnerTrustConfigV1 {
        schema_version: old.schema_version.clone(),
        repository_id: old.repository_id.clone(),
        role: old.role.clone(),
        epoch: rotation.new_epoch,
        key_id: rotation.new_key_id,
        public_key: rotation.new_public_key,
        schema_digests: old.schema_digests.clone(),
        proof_of_possession: rotation.new_proof_of_possession,
        predecessor: Some(old.sha256()?),
    })
}

/// Verify an unbroken chain from its genesis and reject immediate or ABA key reuse.
///
/// # Errors
///
/// Returns a fail-closed error for an invalid genesis, transition, or repeated key identifier.
pub fn verify_rotation_chain(
    genesis: &ProjectOwnerTrustConfigV1,
    rotations: &[KeyRotationV1],
    anchor: &TrustAnchorState,
) -> Result<ProjectOwnerTrustConfigV1, AuthorityError> {
    crate::verify_genesis(genesis)?;
    verify_pinned_chain_member(genesis, anchor)?;
    let mut known = std::collections::BTreeSet::from([genesis.key_id]);
    let mut active = genesis.clone();
    for rotation in rotations {
        let successor = verify_rotation(&active, rotation)?;
        if !known.insert(successor.key_id) {
            return Err(AuthorityError::ReusedRotationKey);
        }
        verify_pinned_chain_member(&successor, anchor)?;
        active = successor;
    }
    verify_chain_anchor(&active, anchor)?;
    Ok(active)
}

/// Build the canonical unsigned payload authorized by the old project-owner key.
///
/// # Errors
///
/// Returns [`AuthorityError::Serialization`] only if canonical JSON cannot be encoded.
pub fn rotation_old_authorization_payload(
    rotation: &KeyRotationV1,
) -> Result<Vec<u8>, AuthorityError> {
    canonical_rotation(rotation, false)
}

/// Build the exact domain-separated old-key authorization transcript.
///
/// # Errors
///
/// Returns an error when the rotation cannot be canonically serialized.
pub fn rotation_old_authorization_transcript(
    rotation: &KeyRotationV1,
) -> Result<Vec<u8>, AuthorityError> {
    framed_transcript(OLD_DOMAIN, &rotation_old_authorization_payload(rotation)?)
}

/// Build the canonical unsigned payload for the new key proof of possession.
///
/// # Errors
///
/// Returns a predecessor error when the payload would not bind the supplied active config.
pub fn rotation_new_pop_payload(
    old: &ProjectOwnerTrustConfigV1,
    rotation: &KeyRotationV1,
) -> Result<Vec<u8>, AuthorityError> {
    if rotation.predecessor_config_sha256 != old.sha256()? {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    canonical_successor_without_pop(old, rotation)
}

/// Build the exact domain-separated new-key proof-of-possession transcript.
///
/// # Errors
///
/// Returns a predecessor error when the transcript would not bind the active config.
pub fn rotation_new_pop_transcript(
    old: &ProjectOwnerTrustConfigV1,
    rotation: &KeyRotationV1,
) -> Result<Vec<u8>, AuthorityError> {
    framed_transcript(NEW_DOMAIN, &rotation_new_pop_payload(old, rotation)?)
}

/// Create the only explicit signal that continuity must stop after compromise.
#[must_use]
pub fn after_explicit_compromise_declaration(
    active: &ProjectOwnerTrustConfigV1,
) -> TrustResetRequired {
    TrustResetRequired {
        repository_id: active.repository_id.clone(),
        compromised_key_id: active.key_id,
        compromised_epoch: active.epoch,
    }
}

fn validate_binding(
    old: &ProjectOwnerTrustConfigV1,
    rotation: &KeyRotationV1,
) -> Result<(), AuthorityError> {
    verify_active_trust_config(old)?;
    if rotation.schema_version != ROTATION_SCHEMA
        || rotation.repository_id != old.repository_id
        || rotation.role != old.role
    {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    if rotation.predecessor_config_sha256 != old.sha256()? {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    if rotation.old_key_id != old.key_id || rotation.old_epoch != old.epoch {
        return Err(AuthorityError::InvalidRotationOldKey);
    }
    if rotation.new_epoch
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
    Ok(())
}

pub fn canonical_rotation(
    rotation: &KeyRotationV1,
    include_old_authorization: bool,
) -> Result<Vec<u8>, AuthorityError> {
    let mut root = BTreeMap::from([
        ("new_epoch", Value::Number(rotation.new_epoch.into())),
        ("new_key_id", Value::String(hex(&rotation.new_key_id))),
        (
            "new_public_key",
            Value::String(URL_SAFE_NO_PAD.encode(rotation.new_public_key)),
        ),
        (
            "new_proof_of_possession",
            Value::String(URL_SAFE_NO_PAD.encode(rotation.new_proof_of_possession)),
        ),
        ("old_epoch", Value::Number(rotation.old_epoch.into())),
        ("old_key_id", Value::String(hex(&rotation.old_key_id))),
        (
            "predecessor_config_sha256",
            Value::String(hex(&rotation.predecessor_config_sha256)),
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

fn canonical_successor_without_pop(
    old: &ProjectOwnerTrustConfigV1,
    rotation: &KeyRotationV1,
) -> Result<Vec<u8>, AuthorityError> {
    canonical_config(
        &ProjectOwnerTrustConfigV1 {
            schema_version: old.schema_version.clone(),
            repository_id: old.repository_id.clone(),
            role: old.role.clone(),
            epoch: rotation.new_epoch,
            key_id: rotation.new_key_id,
            public_key: rotation.new_public_key,
            schema_digests: old.schema_digests.clone(),
            proof_of_possession: [0; 64],
            predecessor: Some(old.sha256()?),
        },
        false,
    )
}
