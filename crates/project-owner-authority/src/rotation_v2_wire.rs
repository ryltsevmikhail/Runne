//! Strict canonical JSON codec for V2 trust rotations.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

use crate::{AuthorityError, KeyRotationV2, SchemaDigest, rotation_v2::canonical_rotation_v2};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: String,
    repository_id: String,
    role: String,
    old_trust_schema_version: String,
    old_trust_config_sha256: String,
    old_key_id: String,
    old_epoch: u64,
    new_trust_schema_version: String,
    new_key_id: String,
    new_public_key: String,
    new_epoch: u64,
    new_schema_digests: Vec<Pin>,
    old_authorization: String,
    new_proof_of_possession: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    schema_id: String,
    schema_sha256: String,
}

pub fn parse(bytes: &[u8]) -> Result<KeyRotationV2, AuthorityError> {
    let wire = serde_json::from_value::<Wire>(crate::strict_json::parse(bytes)?)
        .map_err(|_| AuthorityError::InvalidRotationPredecessor)?;
    let rotation = KeyRotationV2 {
        schema_version: wire.schema_version,
        repository_id: wire.repository_id,
        role: wire.role,
        old_trust_schema_version: wire.old_trust_schema_version,
        old_trust_config_sha256: hex(&wire.old_trust_config_sha256)?,
        old_key_id: hex(&wire.old_key_id)?,
        old_epoch: wire.old_epoch,
        new_trust_schema_version: wire.new_trust_schema_version,
        new_key_id: hex(&wire.new_key_id)?,
        new_public_key: binary(&wire.new_public_key)?,
        new_epoch: wire.new_epoch,
        new_schema_digests: wire
            .new_schema_digests
            .into_iter()
            .map(|pin| {
                Ok(SchemaDigest {
                    schema_id: pin.schema_id,
                    schema_sha256: hex(&pin.schema_sha256)?,
                })
            })
            .collect::<Result<_, AuthorityError>>()?,
        old_authorization: binary(&wire.old_authorization)?,
        new_proof_of_possession: binary(&wire.new_proof_of_possession)?,
    };
    if canonical_rotation_v2(&rotation, true)? != bytes {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    Ok(rotation)
}
fn binary<const N: usize>(value: &str) -> Result<[u8; N], AuthorityError> {
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
fn hex(value: &str) -> Result<[u8; 32], AuthorityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AuthorityError::InvalidRotationPredecessor);
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Ok(output)
}
const fn digit(byte: u8) -> Result<u8, AuthorityError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AuthorityError::InvalidRotationPredecessor),
    }
}
