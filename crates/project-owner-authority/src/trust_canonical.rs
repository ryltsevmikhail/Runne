//! Canonical public trust-configuration serialization.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::{AuthorityError, ProjectOwnerTrustConfigV1, SchemaDigest};

pub fn canonical_config(
    config: &ProjectOwnerTrustConfigV1,
    include_pop: bool,
) -> Result<Vec<u8>, AuthorityError> {
    if config.schema_digests.is_empty()
        || config
            .schema_digests
            .windows(2)
            .any(|pair| pair[0].schema_id.as_bytes() >= pair[1].schema_id.as_bytes())
        || config
            .schema_digests
            .iter()
            .any(|item| !valid_schema_id(&item.schema_id))
    {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    let schemas = config.schema_digests.iter().map(schema_value).collect();
    let mut root = BTreeMap::from([
        ("epoch", Value::Number(config.epoch.into())),
        ("key_id", Value::String(hex(&config.key_id))),
        (
            "predecessor",
            config
                .predecessor
                .map_or(Value::Null, |value| Value::String(hex(&value))),
        ),
        (
            "public_key",
            Value::String(URL_SAFE_NO_PAD.encode(config.public_key)),
        ),
        ("repository_id", Value::String(config.repository_id.clone())),
        ("role", Value::String(config.role.clone())),
        ("schema_digests", Value::Array(schemas)),
        (
            "schema_version",
            Value::String(config.schema_version.clone()),
        ),
    ]);
    if include_pop {
        root.insert(
            "proof_of_possession",
            Value::String(URL_SAFE_NO_PAD.encode(config.proof_of_possession)),
        );
    }
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn valid_schema_id(value: &str) -> bool {
    let Some((name, version)) = value
        .strip_prefix("gocode.")
        .and_then(|rest| rest.split_once('/'))
    else {
        return false;
    };
    !name.is_empty()
        && !version.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]])
        .map(char::from)
        .collect()
}

fn schema_value(item: &SchemaDigest) -> Value {
    Value::Object(
        BTreeMap::from([
            ("schema_id".into(), Value::String(item.schema_id.clone())),
            (
                "schema_sha256".into(),
                Value::String(hex(&item.schema_sha256)),
            ),
        ])
        .into_iter()
        .collect(),
    )
}
