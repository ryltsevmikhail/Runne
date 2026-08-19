//! Canonical encoders for promotion bootstrap receipts.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::{
    AuthorityError,
    receipt_v4::{DelegationV1, PromotionBootstrapV4},
    trust_canonical::hex,
};

/// Serialize a promotion bootstrap into canonical unsigned LF-terminated JSON.
///
/// # Errors
/// Returns an error only when JSON serialization fails.
pub fn canonical_unsigned_promotion_bootstrap(
    value: &PromotionBootstrapV4,
) -> Result<Vec<u8>, AuthorityError> {
    let mut root = BTreeMap::new();
    root.insert(
        "authority_store_profile",
        Value::String(value.authority_store_profile.clone()),
    );
    root.insert(
        "root_principal_id",
        Value::String(value.root_principal_id.clone()),
    );
    root.insert(
        "root_controlling_account_id",
        Value::String(value.root_controlling_account_id.clone()),
    );
    root.insert("root_lane_id", Value::String(value.root_lane_id.clone()));
    root.insert(
        "root_signature_profile_id",
        Value::String(value.root_signature_profile_id.clone()),
    );
    root.insert(
        "delegations",
        Value::Array(value.delegations.iter().map(delegation_value).collect()),
    );
    root.insert(
        "documents",
        Value::Array(
            value
                .documents
                .iter()
                .map(crate::receipt_v4_validation::document_value)
                .collect(),
        ),
    );
    root.insert("expires_at", Value::String(value.expires_at.clone()));
    root.insert("issued_at", Value::String(value.issued_at.clone()));
    root.insert("key_epoch", Value::Number(value.key_epoch.into()));
    root.insert("key_id", Value::String(value.key_id.clone()));
    root.insert("not_before", Value::String(value.not_before.clone()));
    root.insert(
        "platform_matrix_sha256",
        Value::String(hex(&value.platform_matrix_sha256)),
    );
    root.insert(
        "platform_qualified_subject_sha256",
        Value::String(hex(&value.platform_qualified_subject_sha256)),
    );
    root.insert(
        "predecessor_receipt_sha256",
        Value::String(hex(&value.predecessor_receipt_sha256)),
    );
    root.insert("profile", Value::String(value.profile.clone()));
    root.insert(
        "promotion_policy_revision",
        Value::String(value.promotion_policy_revision.clone()),
    );
    root.insert(
        "promotion_policy_sha256",
        Value::String(hex(&value.promotion_policy_sha256)),
    );
    root.insert("purpose", Value::String(value.purpose.clone()));
    root.insert("repository_id", Value::String(value.repository_id.clone()));
    root.insert(
        "revocation_epoch",
        Value::Number(value.revocation_epoch.into()),
    );
    root.insert("role", Value::String(value.role.clone()));
    root.insert(
        "schema_version",
        Value::String(value.schema_version.clone()),
    );
    root.insert(
        "subject",
        crate::receipt_v3::subject_value_v3(&value.subject),
    );
    root.insert(
        "trust_config_sha256",
        Value::String(value.trust_config_sha256.clone()),
    );
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Serialize canonical checked-in bytes including a detached signature.
///
/// # Errors
/// Returns an error only when JSON serialization fails.
pub fn canonical_checked_in_promotion_bootstrap(
    value: &PromotionBootstrapV4,
    signature: &[u8; 64],
) -> Result<Vec<u8>, AuthorityError> {
    let mut root: BTreeMap<String, Value> =
        serde_json::from_slice(&canonical_unsigned_promotion_bootstrap(value)?)
            .map_err(|_| AuthorityError::Serialization)?;
    root.insert(
        "signature".into(),
        Value::String(URL_SAFE_NO_PAD.encode(signature)),
    );
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn delegation_value(value: &DelegationV1) -> Value {
    Value::Object(
        BTreeMap::from([
            (
                "allowed_payload_schema_ids".into(),
                Value::Array(
                    value
                        .allowed_payload_schema_ids
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            ),
            (
                "controlling_account_id".into(),
                Value::String(value.controlling_account_id.clone()),
            ),
            ("expires_at".into(), Value::String(value.expires_at.clone())),
            ("key_epoch".into(), Value::Number(value.key_epoch.into())),
            ("key_id".into(), Value::String(value.key_id.clone())),
            ("lane_id".into(), Value::String(value.lane_id.clone())),
            ("not_before".into(), Value::String(value.not_before.clone())),
            (
                "principal_id".into(),
                Value::String(value.principal_id.clone()),
            ),
            (
                "public_key".into(),
                Value::String(URL_SAFE_NO_PAD.encode(value.public_key)),
            ),
            (
                "revocation_epoch".into(),
                Value::Number(value.revocation_epoch.into()),
            ),
            ("role".into(), Value::String(value.role.clone())),
            (
                "signature_profile_id".into(),
                Value::String(value.signature_profile_id.clone()),
            ),
        ])
        .into_iter()
        .collect(),
    )
}
