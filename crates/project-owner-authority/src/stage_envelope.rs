//! Raw-verifiable, non-executing post-RC0 stage authority envelopes.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    AuthorityError, VerifiedStageIssuer, receipt_v4_validation::hex_digest, trust_canonical::hex,
};

pub use crate::stage_context::{
    StageAdmission, StageAdmissionRequest, StageAdmissionScope, StageVerificationContext,
    VerifiedStageAdmission,
};

/// Fixed schema identifier for post-RC0 stage envelopes.
pub const STAGE_ENVELOPE_SCHEMA_V1: &str = "gocode.release.post-rc0-stage-envelope/1";

/// Canonical unsigned stage envelope fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StageAuthorityEnvelopeV1 {
    /// Stage envelope schema identifier.
    pub schema_version: String,
    /// Bound repository identity.
    pub repository_id: String,
    /// Verified V4 bootstrap digest.
    pub bootstrap_receipt_sha256: [u8; 32],
    /// Delegated issuer role.
    pub issuer_role: String,
    /// Delegated immutable principal identity.
    pub issuer_principal_id: String,
    /// Delegated controlling account identity.
    pub issuer_controlling_account_id: String,
    /// Delegated protected execution lane identity.
    pub issuer_lane_id: String,
    /// Delegated public key identifier.
    pub issuer_key_id: String,
    /// Delegated key epoch.
    pub issuer_key_epoch: u64,
    /// Delegated signature profile identity.
    pub signature_profile_id: String,
    /// Exact payload schema identifier.
    pub payload_schema_id: String,
    /// Pinned payload schema digest.
    pub payload_schema_sha256: [u8; 32],
    /// SHA-256 of canonical payload bytes.
    pub payload_sha256: [u8; 32],
    /// Canonical payload object; never an authority-effect request.
    pub payload: Value,
    /// Envelope issuance time.
    pub issued_at: String,
    /// Envelope validity start.
    pub not_before: String,
    /// Envelope validity end.
    pub expires_at: String,
    /// Required delegated revocation epoch.
    pub revocation_epoch: u64,
    /// Per-envelope authorization replay nonce.
    pub authorization_nonce: String,
}

/// Opaque evidence that strict raw stage-envelope verification completed.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedStageEnvelope {
    // SHA-256 is over the signed canonical envelope bytes without the checked-in LF.
    // Detached signatures and embedded payload digests are likewise LF-excluded.
    envelope_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    schema_id: String,
    typed_payload: gocode_promotion_contracts::ValidatedCanonicalStagePayload,
    payload: Vec<u8>,
    issuer: VerifiedStageIssuer,
    root: VerifiedStageIssuer,
    bootstrap_receipt_sha256: [u8; 32],
    admission: Option<VerifiedStageAdmission>,
}

impl VerifiedStageEnvelope {
    /// Return the SHA-256 of signed canonical stage-envelope bytes without the final LF.
    #[must_use]
    pub const fn envelope_sha256(&self) -> [u8; 32] {
        self.envelope_sha256
    }
    /// Return the verified payload schema identifier.
    #[must_use]
    pub fn payload_schema_id(&self) -> &str {
        &self.schema_id
    }
    /// Return the verified canonical embedded payload digest.
    #[must_use]
    pub const fn payload_sha256(&self) -> [u8; 32] {
        self.payload_sha256
    }
    /// Return the exact verified canonical embedded payload bytes.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload
    }
    /// Return the neutral typed validation result coupled to this verified envelope.
    #[must_use]
    pub const fn typed_payload(
        &self,
    ) -> &gocode_promotion_contracts::ValidatedCanonicalStagePayload {
        &self.typed_payload
    }
    /// Return the issuer identity bound by the verified signed envelope.
    #[must_use]
    pub const fn issuer(&self) -> &VerifiedStageIssuer {
        &self.issuer
    }
    /// Return the root identity bound by the verified bootstrap receipt.
    #[must_use]
    pub const fn root(&self) -> &VerifiedStageIssuer {
        &self.root
    }
    /// Return the exact verified V4 bootstrap receipt digest.
    #[must_use]
    pub const fn bootstrap_receipt_sha256(&self) -> [u8; 32] {
        self.bootstrap_receipt_sha256
    }
    /// Consume the envelope's provisional admission facts for one store transition.
    #[must_use]
    pub fn into_admission(self) -> Option<VerifiedStageAdmission> {
        self.admission
    }
}

pub(crate) fn verified_stage_envelope(
    envelope_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    schema_id: String,
    payload: Vec<u8>,
    identities: (VerifiedStageIssuer, VerifiedStageIssuer),
    bootstrap_receipt_sha256: [u8; 32],
    admission: Option<VerifiedStageAdmission>,
) -> VerifiedStageEnvelope {
    let typed_payload = gocode_promotion_contracts::validate_stage_payload(&schema_id, &payload)
        .expect("verified stage envelope only mints after neutral validation");
    VerifiedStageEnvelope {
        envelope_sha256,
        payload_sha256,
        schema_id,
        typed_payload,
        payload,
        issuer: identities.0,
        root: identities.1,
        bootstrap_receipt_sha256,
        admission,
    }
}

/// Serialize a payload object to canonical JSON bytes without a trailing line feed.
///
/// # Errors
/// Returns an error only when JSON serialization fails.
pub fn canonical_stage_payload(value: &Value) -> Result<Vec<u8>, AuthorityError> {
    if !value.is_object() || contains_enclosing_hash(value) {
        return Err(AuthorityError::InvalidStageEnvelope);
    }
    let canonical = canonical_value(value);
    serde_json::to_vec(&canonical).map_err(|_| AuthorityError::Serialization)
}

/// Serialize unsigned stage-envelope fields to canonical bytes without a final LF.
///
/// These bytes are the detached-signature transcript preimage. The checked-in
/// envelope serializer adds exactly one final LF after inserting its signature.
///
/// # Errors
/// Returns an error only when payload or JSON serialization is invalid.
pub fn canonical_unsigned_stage_envelope(
    value: &StageAuthorityEnvelopeV1,
) -> Result<Vec<u8>, AuthorityError> {
    let mut root = BTreeMap::new();
    root.insert(
        "bootstrap_receipt_sha256",
        Value::String(hex(&value.bootstrap_receipt_sha256)),
    );
    root.insert("expires_at", Value::String(value.expires_at.clone()));
    root.insert("issued_at", Value::String(value.issued_at.clone()));
    root.insert(
        "issuer_controlling_account_id",
        Value::String(value.issuer_controlling_account_id.clone()),
    );
    root.insert(
        "issuer_key_epoch",
        Value::Number(value.issuer_key_epoch.into()),
    );
    root.insert("issuer_key_id", Value::String(value.issuer_key_id.clone()));
    root.insert(
        "issuer_principal_id",
        Value::String(value.issuer_principal_id.clone()),
    );
    root.insert("issuer_role", Value::String(value.issuer_role.clone()));
    root.insert(
        "issuer_lane_id",
        Value::String(value.issuer_lane_id.clone()),
    );
    root.insert(
        "authorization_nonce",
        Value::String(value.authorization_nonce.clone()),
    );
    root.insert("not_before", Value::String(value.not_before.clone()));
    root.insert("payload", value.payload.clone());
    root.insert(
        "payload_schema_id",
        Value::String(value.payload_schema_id.clone()),
    );
    root.insert(
        "payload_schema_sha256",
        Value::String(hex(&value.payload_schema_sha256)),
    );
    root.insert("payload_sha256", Value::String(hex(&value.payload_sha256)));
    root.insert("repository_id", Value::String(value.repository_id.clone()));
    root.insert(
        "revocation_epoch",
        Value::Number(value.revocation_epoch.into()),
    );
    root.insert(
        "schema_version",
        Value::String(value.schema_version.clone()),
    );
    root.insert(
        "signature_profile_id",
        Value::String(value.signature_profile_id.clone()),
    );
    serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)
}

/// Serialize checked-in canonical stage-envelope bytes including detached signature and one LF.
///
/// # Errors
/// Returns an error only when payload or JSON serialization is invalid.
pub fn canonical_checked_in_stage_envelope(
    value: &StageAuthorityEnvelopeV1,
    signature: &[u8; 64],
) -> Result<Vec<u8>, AuthorityError> {
    let mut root: BTreeMap<String, Value> =
        serde_json::from_slice(&canonical_unsigned_stage_envelope(value)?)
            .map_err(|_| AuthorityError::Serialization)?;
    root.insert(
        "signature".into(),
        Value::String(URL_SAFE_NO_PAD.encode(signature)),
    );
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn validate_stage_fields(
    value: &StageAuthorityEnvelopeV1,
) -> Result<(), AuthorityError> {
    if value.schema_version != STAGE_ENVELOPE_SCHEMA_V1
        || value.repository_id != "gocode"
        || !hex_digest(&value.issuer_key_id)
        || !crate::receipt_v4_validation::safe_id(&value.authorization_nonce)
        || value.issuer_key_epoch == 0
        || value.revocation_epoch == 0
        || !ordered(&value.issued_at, &value.not_before, &value.expires_at)
    {
        return Err(AuthorityError::InvalidStageEnvelope);
    }
    canonical_stage_payload(&value.payload)?;
    Ok(())
}

fn ordered(first: &str, second: &str, third: &str) -> bool {
    crate::receipt_validation::valid_timestamp(first)
        && crate::receipt_validation::valid_timestamp(second)
        && crate::receipt_validation::valid_timestamp(third)
        && first < second
        && second < third
}
fn contains_enclosing_hash(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(contains_enclosing_hash),
        Value::Object(items) => items.iter().any(|(key, item)| {
            key == "envelope_sha256"
                || key == "stage_envelope_sha256"
                || contains_enclosing_hash(item)
        }),
        _ => false,
    }
}
fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        Value::Object(items) => Value::Object(
            items
                .iter()
                .map(|(key, item)| (key.clone(), canonical_value(item)))
                .collect(),
        ),
        _ => value.clone(),
    }
}
