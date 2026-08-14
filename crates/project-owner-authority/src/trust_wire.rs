//! Exact canonical JSON codec for public project-owner trust configurations.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

use crate::{
    AuthorityError, ProjectOwnerTrustConfigV1, SchemaDigest, trust_canonical::canonical_config,
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
    schema_digests: Vec<WireSchemaDigest>,
    proof_of_possession: String,
    predecessor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSchemaDigest {
    schema_id: String,
    schema_sha256: String,
}

pub fn parse(bytes: &[u8]) -> Result<ProjectOwnerTrustConfigV1, AuthorityError> {
    let wire = serde_json::from_value::<Wire>(crate::strict_json::parse(bytes)?)
        .map_err(|_| AuthorityError::InvalidGenesis)?;
    let config = ProjectOwnerTrustConfigV1 {
        schema_version: wire.schema_version,
        repository_id: wire.repository_id,
        role: wire.role,
        epoch: wire.epoch,
        key_id: decode_hex(&wire.key_id)?,
        public_key: decode_binary(&wire.public_key)?,
        schema_digests: wire
            .schema_digests
            .into_iter()
            .map(|item| {
                Ok(SchemaDigest {
                    schema_id: item.schema_id,
                    schema_sha256: decode_hex(&item.schema_sha256)?,
                })
            })
            .collect::<Result<_, AuthorityError>>()?,
        proof_of_possession: decode_binary(&wire.proof_of_possession)?,
        predecessor: wire
            .predecessor
            .map(|value| decode_hex(&value))
            .transpose()?,
    };
    if canonical_config(&config, true)? != bytes {
        return Err(AuthorityError::InvalidGenesis);
    }
    Ok(config)
}

fn decode_binary<const N: usize>(value: &str) -> Result<[u8; N], AuthorityError> {
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

fn decode_hex(value: &str) -> Result<[u8; 32], AuthorityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AuthorityError::InvalidGenesis);
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
        _ => Err(AuthorityError::InvalidGenesis),
    }
}

impl ProjectOwnerTrustConfigV1 {
    /// Parse only exact canonical project-owner trust-configuration JSON.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for duplicate, unknown, malformed, or noncanonical input.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorityError> {
        parse(bytes)
    }

    /// Return exact canonical trust-configuration JSON, including one final LF.
    ///
    /// # Errors
    ///
    /// Returns an error when schema digests are not canonically ordered and unique.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, AuthorityError> {
        canonical_config(self, true)
    }
}
