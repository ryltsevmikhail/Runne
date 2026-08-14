//! Exact canonical JSON codec for public project-owner key rotations.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

use crate::{AuthorityError, KeyRotationV1, rotation::canonical_rotation};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: String,
    repository_id: String,
    role: String,
    predecessor_config_sha256: String,
    old_key_id: String,
    old_epoch: u64,
    new_key_id: String,
    new_public_key: String,
    new_epoch: u64,
    old_authorization: String,
    new_proof_of_possession: String,
}

pub fn parse(bytes: &[u8]) -> Result<KeyRotationV1, AuthorityError> {
    let wire = serde_json::from_value::<Wire>(crate::strict_json::parse(bytes)?)
        .map_err(|_| AuthorityError::InvalidRotationPredecessor)?;
    let rotation = KeyRotationV1 {
        schema_version: wire.schema_version,
        repository_id: wire.repository_id,
        role: wire.role,
        predecessor_config_sha256: decode_hex(&wire.predecessor_config_sha256)?,
        old_key_id: decode_hex(&wire.old_key_id)?,
        old_epoch: wire.old_epoch,
        new_key_id: decode_hex(&wire.new_key_id)?,
        new_public_key: decode_binary(&wire.new_public_key)?,
        new_epoch: wire.new_epoch,
        old_authorization: decode_binary(&wire.old_authorization)?,
        new_proof_of_possession: decode_binary(&wire.new_proof_of_possession)?,
    };
    if canonical_rotation(&rotation, true)? != bytes {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    Ok(rotation)
}

fn decode_binary<const N: usize>(value: &str) -> Result<[u8; N], AuthorityError> {
    if value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthorityError::InvalidRotationPredecessor)?
        .try_into()
        .map_err(|_| AuthorityError::InvalidRotationPredecessor)
}

fn decode_hex(value: &str) -> Result<[u8; 32], AuthorityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = hex_digit(pair[0])? << 4 | hex_digit(pair[1])?;
    }
    Ok(output)
}

const fn hex_digit(value: u8) -> Result<u8, AuthorityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthorityError::InvalidRotationPredecessor),
    }
}

impl KeyRotationV1 {
    /// Parse only exact canonical project-owner key-rotation JSON.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for duplicate, unknown, malformed, or noncanonical input.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorityError> {
        parse(bytes)
    }

    /// Return exact canonical key-rotation JSON, including one final LF.
    ///
    /// # Errors
    ///
    /// Returns an error only when canonical serialization cannot be produced.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, AuthorityError> {
        canonical_rotation(self, true)
    }
}
