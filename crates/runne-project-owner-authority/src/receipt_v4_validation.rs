//! Closed V4 promotion bootstrap validation.
use crate::{
    AuthorityError, Document, PromotionBootstrapV4,
    receipt_v4::{PROFILE_V4, PURPOSE_V4, RECEIPT_SCHEMA_V4, ROLES},
    receipt_v4_profile::DOCUMENTS,
    receipt_validation,
    trust_canonical::hex,
};
use serde_json::Value;

pub(crate) fn document_value(value: &Document) -> Value {
    let mut item = std::collections::BTreeMap::from([
        ("blob_oid".into(), Value::String(value.blob_oid.clone())),
        (
            "byte_length".into(),
            Value::Number(value.byte_length.into()),
        ),
        (
            "content_sha256".into(),
            Value::String(value.content_sha256.clone()),
        ),
        ("mode".into(), Value::String(value.mode.clone())),
        ("path".into(), Value::String(value.path.clone())),
    ]);
    if let Some(schema) = &value.schema_id {
        item.insert("schema_id".into(), Value::String(schema.clone()));
    }
    Value::Object(item.into_iter().collect())
}
use std::collections::BTreeSet;
pub(crate) fn validate_bootstrap(
    value: &PromotionBootstrapV4,
    root: [u8; 32],
) -> Result<(), AuthorityError> {
    if value.schema_version != RECEIPT_SCHEMA_V4
        || value.repository_id != "gocode"
        || value.role != "PROJECT_OWNER"
        || value.purpose != PURPOSE_V4
        || value.profile != PROFILE_V4
        || value.key_epoch < 3
        || value.revocation_epoch == 0
        || !ordered(&value.issued_at, &value.not_before, &value.expires_at)
        || !hex_digest(&value.trust_config_sha256)
        || !hex_digest(&value.key_id)
        || !safe_id(&value.promotion_policy_revision)
        || !safe_id(&value.authority_store_profile)
        || !safe_id(&value.root_principal_id)
        || !safe_id(&value.root_controlling_account_id)
        || !safe_id(&value.root_lane_id)
        || !safe_id(&value.root_signature_profile_id)
    {
        return Err(AuthorityError::InvalidPromotionBootstrap);
    }
    let width = receipt_validation::subject_oid_width(&value.subject)?;
    if value.documents.len() != DOCUMENTS.len()
        || value
            .documents
            .iter()
            .zip(DOCUMENTS)
            .any(|(item, expected)| {
                item.path != expected.path
                    || item.mode != expected.mode
                    || item.blob_oid != expected.blob_oid
                    || item.content_sha256 != expected.content_sha256
                    || item.byte_length != expected.byte_length
                    || item.schema_id.as_deref() != expected.schema_id
                    || !receipt_validation::lower_hex(&item.blob_oid, width)
                    || !hex_digest(&item.content_sha256)
            })
    {
        return Err(AuthorityError::InvalidPromotionBootstrap);
    }
    if value.delegations.len() != 3
        || value
            .delegations
            .iter()
            .map(|item| item.role.as_str())
            .collect::<Vec<_>>()
            != ROLES
    {
        return Err(AuthorityError::InvalidDelegation);
    }
    let mut principal = BTreeSet::from([&value.root_principal_id]);
    let mut account = BTreeSet::from([&value.root_controlling_account_id]);
    let mut lane = BTreeSet::from([&value.root_lane_id]);
    let mut key = BTreeSet::from([&value.key_id]);
    let mut public = BTreeSet::new();
    let mut profile = BTreeSet::from([&value.root_signature_profile_id]);
    for item in &value.delegations {
        if !safe_id(&item.principal_id)
            || !safe_id(&item.controlling_account_id)
            || !safe_id(&item.lane_id)
            || !safe_id(&item.signature_profile_id)
            || item.key_epoch == 0
            || item.revocation_epoch == 0
            || !ordered(&value.not_before, &item.not_before, &item.expires_at)
            || item.expires_at > value.expires_at
            || item.key_id != hex(&crate::key_id(&item.public_key))
            || item.public_key == root
            || item.key_id == value.key_id
            || item.allowed_payload_schema_ids != allowed(&item.role)
            || !principal.insert(&item.principal_id)
            || !account.insert(&item.controlling_account_id)
            || !lane.insert(&item.lane_id)
            || !key.insert(&item.key_id)
            || !public.insert(item.public_key)
            || !profile.insert(&item.signature_profile_id)
        {
            return Err(AuthorityError::InvalidDelegation);
        }
    }
    Ok(())
}
pub(crate) fn allowed(role: &str) -> Vec<String> {
    match role {
        "RC1_QUALIFICATION_AUTHORIZER" => {
            vec!["gocode.release.rc1-qualification-decision/1".into()]
        }
        "RC2_SIGNING_AUTHORIZER" => vec!["gocode.release.rc2-signing-authorization/1".into()],
        "RC3_PUBLICATION_AUTHORIZER" => {
            vec!["gocode.release.rc3-publication-authorization/1".into()]
        }
        _ => vec![],
    }
}
fn ordered(a: &str, b: &str, c: &str) -> bool {
    receipt_validation::valid_timestamp(a)
        && receipt_validation::valid_timestamp(b)
        && receipt_validation::valid_timestamp(c)
        && a < b
        && b < c
}
pub(crate) fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
pub(crate) fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}
