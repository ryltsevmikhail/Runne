//! V2 evidence envelope opaque result used by RC2/RC3 release consumers.

use serde::Deserialize;
use serde_json::Value;

/// Fixed raw evidence envelope schema for V5 evidence delegations.
pub const EVIDENCE_ENVELOPE_SCHEMA_V2: &str = "gocode.release.post-rc0-evidence-envelope/2";

/// Raw V2 evidence authorization envelope, signed only by an evidence delegate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuthorityEnvelopeV2 {
    pub schema_version: String,
    pub repository_id: String,
    pub receipt_sha256: [u8; 32],
    pub trust_config_sha256: String,
    pub trust_generation: u64,
    pub issuer_role: String,
    pub issuer_scope: String,
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

/// Move-only verification result retaining exact evidence admission facts.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedEvidenceEnvelopeV2 {
    envelope_sha256: [u8; 32],
    receipt_sha256: [u8; 32],
    trust_generation: u64,
    payload_sha256: [u8; 32],
    payload_schema_id: String,
    payload: Vec<u8>,
    issuer: crate::DelegationV2,
    validity: crate::EnvelopeValidityV2,
}
/// Cryptographically complete, non-authorizing evidence-envelope `/2` result.
///
/// ```compile_fail
/// fn authorize(value: gocode_project_owner_authority::PrevalidatedEvidenceEnvelopeV2) {
///     let _ = value.payload();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct PrevalidatedEvidenceEnvelopeV2 {
    pub(crate) envelope_sha256: [u8; 32],
    pub(crate) receipt_sha256: [u8; 32],
    pub(crate) payload_sha256: [u8; 32],
    pub(crate) payload_schema_id: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) issuer: crate::DelegationV2,
    pub(crate) validity: crate::EnvelopeValidityV2,
    pub(crate) scope: crate::V5AdmissionScope,
}
impl VerifiedEvidenceEnvelopeV2 {
    #[must_use]
    pub const fn envelope_sha256(&self) -> [u8; 32] {
        self.envelope_sha256
    }
    #[must_use]
    pub const fn receipt_sha256(&self) -> [u8; 32] {
        self.receipt_sha256
    }
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
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
    pub const fn validity(&self) -> &crate::EnvelopeValidityV2 {
        &self.validity
    }
}
/// Specialized opaque evidence result for the `(RC3_FINAL_REVIEWER, final-review)` scope.
pub type VerifiedRc3FinalReviewEvidence = VerifiedEvidenceEnvelopeV2;

/// Crate-only mint: a verified evidence envelope is produced exclusively by raw verification.
#[expect(
    clippy::too_many_arguments,
    reason = "every admission fact is retained by the move-only handle"
)]
pub const fn verified_evidence_envelope_v2(
    envelope_sha256: [u8; 32],
    receipt_sha256: [u8; 32],
    trust_generation: u64,
    payload_sha256: [u8; 32],
    payload_schema_id: String,
    payload: Vec<u8>,
    issuer: crate::DelegationV2,
    validity: crate::EnvelopeValidityV2,
) -> VerifiedEvidenceEnvelopeV2 {
    VerifiedEvidenceEnvelopeV2 {
        envelope_sha256,
        receipt_sha256,
        trust_generation,
        payload_sha256,
        payload_schema_id,
        payload,
        issuer,
        validity,
    }
}
