//! Strict canonical JSON codec for V2 trust configurations.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

use crate::{
    AuthorityError, ProjectOwnerTrustConfigV2, SchemaDigest, trust_v2::canonical_config_v2,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: String,
    repository_id: String,
    role: String,
    epoch: u64,
    key_id: String,
    public_key: String,
    schema_digests: Vec<Pin>,
    proof_of_possession: String,
    predecessor: String,
    predecessor_schema_version: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    schema_id: String,
    schema_sha256: String,
}

pub fn parse(bytes: &[u8]) -> Result<ProjectOwnerTrustConfigV2, AuthorityError> {
    let wire = serde_json::from_value::<Wire>(crate::strict_json::parse(bytes)?)
        .map_err(|_| AuthorityError::InvalidGenesis)?;
    let trust = ProjectOwnerTrustConfigV2 {
        schema_version: wire.schema_version,
        repository_id: wire.repository_id,
        role: wire.role,
        epoch: wire.epoch,
        key_id: hex(&wire.key_id)?,
        public_key: binary(&wire.public_key)?,
        schema_digests: wire
            .schema_digests
            .into_iter()
            .map(|pin| {
                Ok(SchemaDigest {
                    schema_id: pin.schema_id,
                    schema_sha256: hex(&pin.schema_sha256)?,
                })
            })
            .collect::<Result<_, AuthorityError>>()?,
        proof_of_possession: binary(&wire.proof_of_possession)?,
        predecessor: hex(&wire.predecessor)?,
        predecessor_schema_version: wire.predecessor_schema_version,
    };
    if canonical_config_v2(&trust, true)? != bytes {
        return Err(AuthorityError::InvalidGenesis);
    }
    Ok(trust)
}

fn binary<const N: usize>(value: &str) -> Result<[u8; N], AuthorityError> {
    if value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(AuthorityError::InvalidGenesis);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthorityError::InvalidGenesis)?
        .try_into()
        .map_err(|_| AuthorityError::InvalidGenesis)
}
fn hex(value: &str) -> Result<[u8; 32], AuthorityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AuthorityError::InvalidGenesis);
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
        _ => Err(AuthorityError::InvalidGenesis),
    }
}
