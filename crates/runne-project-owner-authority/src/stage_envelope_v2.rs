//! V2 stage-envelope model for receipt `/5` transition authority only.

use serde::Deserialize;
use serde_json::Value;

/// The sole active stage envelope schema for versioned V5 promotion authority.
pub const STAGE_ENVELOPE_SCHEMA_V2: &str = "runne.release.post-rc0-stage-envelope/2";

/// Raw V2 transition authorization envelope, signed only by a transition delegate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StageAuthorityEnvelopeV2 {
    pub schema_version: String,
    pub repository_id: String,
    pub receipt_sha256: [u8; 32],
    pub trust_config_sha256: String,
    pub trust_generation: u64,
    pub issuer_role: String,
    pub issuer_principal_id: String,
    pub issuer_controlling_account_id: String,
    pub issuer_lane_id: String,
    pub issuer_key_id: String,
    pub issuer_key_epoch: u64,
    pub signature_profile_id: String,
    pub payload_schema_id: String,
    pub payload_schema_sha256: [u8; 32],
    pub payload_sha256: [u8; 32],
    pub payload: Value,
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
    pub revocation_epoch: u64,
    pub authorization_nonce: String,
}

/// Opaque V2 stage envelope verified against an exact V5 receipt delegation.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedStageEnvelopeV2 {
    envelope_sha256: [u8; 32],
    receipt_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    payload_schema_id: String,
    payload: Vec<u8>,
    issuer: crate::DelegationV2,
    validity: EnvelopeValidityV2,
}
/// Cryptographically complete, non-authorizing stage-envelope `/2` result.
///
/// It deliberately exposes no authorization or payload API:
/// ```compile_fail
/// fn authorize(value: runne_project_owner_authority::PrevalidatedStageEnvelopeV2) {
///     let _ = value.payload();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct PrevalidatedStageEnvelopeV2 {
    pub(crate) envelope_sha256: [u8; 32],
    pub(crate) receipt_sha256: [u8; 32],
    pub(crate) payload_sha256: [u8; 32],
    pub(crate) payload_schema_id: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) issuer: crate::DelegationV2,
    pub(crate) validity: EnvelopeValidityV2,
    pub(crate) scope: crate::V5AdmissionScope,
}
/// Exact issuer and validity facts retained for durable stage admission/recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeValidityV2 {
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
    pub revocation_epoch: u64,
    pub authorization_nonce: String,
    pub trust_generation: u64,
}
impl VerifiedStageEnvelopeV2 {
    #[must_use]
    pub const fn envelope_sha256(&self) -> [u8; 32] {
        self.envelope_sha256
    }
    #[must_use]
    pub const fn receipt_sha256(&self) -> [u8; 32] {
        self.receipt_sha256
    }
    #[must_use]
    pub const fn payload_sha256(&self) -> [u8; 32] {
        self.payload_sha256
    }
    #[must_use]
    pub fn payload_schema_id(&self) -> &str {
        &self.payload_schema_id
    }
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    #[must_use]
    pub const fn issuer(&self) -> &crate::DelegationV2 {
        &self.issuer
    }
    #[must_use]
    pub const fn validity(&self) -> &EnvelopeValidityV2 {
        &self.validity
    }
}

/// Crate-only mint: a verified stage envelope is produced exclusively by raw verification.
pub const fn verified_stage_envelope_v2(
    envelope_sha256: [u8; 32],
    receipt_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    payload_schema_id: String,
    payload: Vec<u8>,
    issuer: crate::DelegationV2,
    validity: EnvelopeValidityV2,
) -> VerifiedStageEnvelopeV2 {
    VerifiedStageEnvelopeV2 {
        envelope_sha256,
        receipt_sha256,
        payload_sha256,
        payload_schema_id,
        payload,
        issuer,
        validity,
    }
}
