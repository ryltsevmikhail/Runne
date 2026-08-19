//! Fail-closed raw admission front doors for the V5 authority generation.
//!
//! These `_bytes` entrypoints perform only structural version/canonical/field checks and
//! the fail-closed V4 pin barrier. The full cryptographic verifiers are the primary API:
//! `verify_promotion_authority_receipt_v5`, `verify_stage_envelope_v2`,
//! `verify_evidence_envelope_v2`, and `verify_destination_allowlist_v1`.

use serde_json::Value;

use crate::{
    AuthorityError, DESTINATION_ALLOWLIST_SCHEMA_V1, EVIDENCE_ENVELOPE_SCHEMA_V2,
    RECEIPT_SCHEMA_V5, STAGE_ENVELOPE_SCHEMA_V2,
};

/// Check a raw V5 receipt before any trusted context is touched.
///
/// # Errors
/// Returns `AUTHORITY_VERSION_SUPERSEDED` for legacy/mixed receipt versions and the explicit
/// V4 pin barrier until all successor schemas have immutable digest pins.
pub fn verify_promotion_authority_receipt_v5_bytes(bytes: &[u8]) -> Result<(), AuthorityError> {
    exact_version(bytes, RECEIPT_SCHEMA_V5, RECEIPT_FIELDS)?;
    crate::v4_trust_schema_digests().map(|_| ())
}

/// Check a raw V2 transition envelope before any nonce or durable state is touched.
///
/// # Errors
/// Returns `AUTHORITY_VERSION_SUPERSEDED` for legacy/mixed envelope versions and the explicit
/// V4 pin barrier until all successor schemas have immutable digest pins.
pub fn verify_stage_envelope_v2_bytes(bytes: &[u8]) -> Result<(), AuthorityError> {
    exact_version(bytes, STAGE_ENVELOPE_SCHEMA_V2, STAGE_FIELDS)?;
    crate::v4_trust_schema_digests().map(|_| ())
}

/// Check a raw V2 evidence envelope before any nonce or durable state is touched.
///
/// # Errors
/// Returns `AUTHORITY_VERSION_SUPERSEDED` for legacy/mixed envelope versions and the explicit
/// V4 pin barrier until all successor schemas have immutable digest pins.
pub fn verify_evidence_envelope_v2_bytes(bytes: &[u8]) -> Result<(), AuthorityError> {
    exact_version(bytes, EVIDENCE_ENVELOPE_SCHEMA_V2, EVIDENCE_FIELDS)?;
    crate::v4_trust_schema_digests().map(|_| ())
}

/// Check a raw root-signed allowlist before any trusted context is touched.
///
/// # Errors
/// Returns `AUTHORITY_VERSION_SUPERSEDED` for a wrong version and the explicit V4 pin barrier
/// until root signature verification can bind the final active trust generation.
pub fn verify_destination_allowlist_v1_bytes(bytes: &[u8]) -> Result<(), AuthorityError> {
    exact_version(bytes, DESTINATION_ALLOWLIST_SCHEMA_V1, ALLOWLIST_FIELDS)?;
    crate::v4_trust_schema_digests().map(|_| ())
}

fn exact_version(bytes: &[u8], expected: &str, fields: &[&str]) -> Result<(), AuthorityError> {
    if std::str::from_utf8(bytes).is_err() {
        return Err(AuthorityError::InvalidUtf8);
    }
    let value = crate::strict_json::parse(bytes)?;
    let Some(object) = value.as_object() else {
        return Err(AuthorityError::InvalidJson);
    };
    let Some(actual) = object.get("schema_version").and_then(Value::as_str) else {
        return Err(AuthorityError::InvalidJson);
    };
    if actual != expected {
        return Err(AuthorityError::AuthorityVersionSuperseded);
    }
    if !canonical_wire(bytes, &value) {
        return Err(AuthorityError::InvalidCanonicalReceipt);
    }
    if let Some(name) = object.keys().find(|name| !fields.contains(&name.as_str())) {
        return Err(AuthorityError::UnknownField(name.clone()));
    }
    Ok(())
}

fn canonical_wire(bytes: &[u8], value: &Value) -> bool {
    let mut canonical = Vec::new();
    write_canonical(value, &mut canonical).is_ok() && {
        canonical.push(b'\n');
        canonical == bytes
    }
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<(), AuthorityError> {
    match value {
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            for (index, (key, value)) in values
                .iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .enumerate()
            {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|_| AuthorityError::Serialization)?;
                output.push(b':');
                write_canonical(value, output)?;
            }
            output.push(b'}');
        }
        _ => serde_json::to_writer(output, value).map_err(|_| AuthorityError::Serialization)?,
    }
    Ok(())
}

const RECEIPT_FIELDS: &[&str] = &[
    "adr_0029_sha256",
    "authority_store_profile",
    "destination_allowlist_generation",
    "destination_allowlist_sha256",
    "evidence_delegations",
    "expires_at",
    "issued_at",
    "key_epoch",
    "key_id",
    "not_before",
    "platform_matrix_sha256",
    "platform_qualified_subject_sha256",
    "post_rc0_program_sha256",
    "predecessor_receipt_sha256",
    "production_security_review_sha256",
    "profile",
    "promotion_policy_revision",
    "promotion_policy_sha256",
    "purpose",
    "repository_id",
    "revocation_epoch",
    "role",
    "root_controlling_account_id",
    "root_lane_id",
    "root_principal_id",
    "root_signature_profile_id",
    "schema_version",
    "signature",
    "subject",
    "transition_delegations",
    "trust_config_sha256",
    "trust_generation",
];
const STAGE_FIELDS: &[&str] = &[
    "authorization_nonce",
    "expires_at",
    "issued_at",
    "issuer_controlling_account_id",
    "issuer_key_epoch",
    "issuer_key_id",
    "issuer_lane_id",
    "issuer_principal_id",
    "issuer_role",
    "not_before",
    "payload",
    "payload_schema_id",
    "payload_schema_sha256",
    "payload_sha256",
    "receipt_sha256",
    "repository_id",
    "revocation_epoch",
    "schema_version",
    "signature",
    "signature_profile_id",
    "trust_config_sha256",
    "trust_generation",
];
const EVIDENCE_FIELDS: &[&str] = &[
    "authorization_nonce",
    "expires_at",
    "issued_at",
    "issuer_controlling_account_id",
    "issuer_key_epoch",
    "issuer_key_id",
    "issuer_lane_id",
    "issuer_principal_id",
    "issuer_role",
    "issuer_scope",
    "not_before",
    "payload",
    "payload_schema_id",
    "payload_schema_sha256",
    "payload_sha256",
    "receipt_sha256",
    "repository_id",
    "revocation_epoch",
    "schema_version",
    "signature",
    "signature_profile_id",
    "trust_config_sha256",
    "trust_generation",
];
const ALLOWLIST_FIELDS: &[&str] = &[
    "destinations",
    "expires_at",
    "generation",
    "issued_at",
    "key_epoch",
    "key_id",
    "not_before",
    "policy_id",
    "repository_id",
    "revocation_epoch",
    "schema_version",
    "signature",
];
