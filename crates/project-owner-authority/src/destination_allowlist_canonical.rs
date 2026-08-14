//! Canonical unsigned and checked-in bytes for destination allowlist `/1`.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::{
    AuthorityError, PublicationDestinationAllowlistV1, PublicationDestinationV1,
    trust_canonical::hex,
};

/// Serialize unsigned allowlist `/1` fields as sorted canonical bytes.
///
/// These bytes omit the final LF and are the detached-signature transcript preimage.
///
/// # Errors
/// Returns an error only when JSON serialization fails.
pub fn canonical_unsigned_allowlist_v1(
    value: &PublicationDestinationAllowlistV1,
) -> Result<Vec<u8>, AuthorityError> {
    let mut root = BTreeMap::new();
    root.insert(
        "destinations",
        Value::Array(value.destinations.iter().map(destination_value).collect()),
    );
    root.insert("expires_at", Value::String(value.expires_at.clone()));
    root.insert("generation", Value::Number(value.generation.into()));
    root.insert("issued_at", Value::String(value.issued_at.clone()));
    root.insert("key_epoch", Value::Number(value.key_epoch.into()));
    root.insert("key_id", Value::String(value.key_id.clone()));
    root.insert("not_before", Value::String(value.not_before.clone()));
    root.insert("policy_id", Value::String(value.policy_id.clone()));
    root.insert("repository_id", Value::String(value.repository_id.clone()));
    root.insert(
        "revocation_epoch",
        Value::Number(value.revocation_epoch.into()),
    );
    root.insert(
        "schema_version",
        Value::String(value.schema_version.clone()),
    );
    serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)
}

/// Serialize checked-in allowlist `/1` bytes including detached signature and one LF.
///
/// # Errors
/// Returns an error only when JSON serialization fails.
pub fn canonical_checked_in_allowlist_v1(
    value: &PublicationDestinationAllowlistV1,
    signature: &[u8; 64],
) -> Result<Vec<u8>, AuthorityError> {
    let mut root: BTreeMap<String, Value> =
        serde_json::from_slice(&canonical_unsigned_allowlist_v1(value)?)
            .map_err(|_| AuthorityError::Serialization)?;
    root.insert(
        "signature".into(),
        Value::String(URL_SAFE_NO_PAD.encode(signature)),
    );
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn destination_value(item: &PublicationDestinationV1) -> Value {
    let value = BTreeMap::from([
        ("channel", Value::String(item.channel.clone())),
        ("destination", Value::String(item.destination.clone())),
        (
            "executor_policy_sha256",
            Value::String(hex(&item.executor_policy_sha256)),
        ),
        (
            "permitted_effect_kinds",
            Value::Array(
                item.permitted_effect_kinds
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        ),
    ]);
    Value::Object(
        value
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
