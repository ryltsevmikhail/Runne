//! Trusted atomic admission contexts for V5 stage, evidence, and allowlist authority.

use crate::{AuthorityError, GitSubject};

/// Immutable receipt `/5` authority facts that a trusted backend admits atomically.
///
/// Recovery equivalence must additionally require the exact `receipt_sha256` (which
/// covers root identity, delegations and every constant binding) together with the
/// retained scope and validity; any divergent field rejects before mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptV5AdmissionScope {
    pub receipt_sha256: [u8; 32],
    pub trust_config_sha256: String,
    pub trust_generation: u64,
    pub predecessor_receipt_sha256: [u8; 32],
    pub authority_store_profile: String,
    pub root_key_id: String,
    pub root_key_epoch: u64,
    pub root_principal_id: String,
    pub root_controlling_account_id: String,
    pub root_lane_id: String,
    pub root_signature_profile_id: String,
    pub root_public_key: [u8; 32],
    pub root_revocation_epoch: u64,
    pub subject: GitSubject,
    pub production_security_review_sha256: [u8; 32],
    pub destination_allowlist_sha256: [u8; 32],
    pub destination_allowlist_generation: u64,
    pub role_scope_floors: Vec<crate::RoleScopeFloor>,
    pub promotion_policy_sha256: [u8; 32],
    pub promotion_policy_revision: String,
    pub platform_qualified_subject_sha256: [u8; 32],
    pub platform_matrix_sha256: [u8; 32],
    pub adr_0029_sha256: [u8; 32],
    pub post_rc0_program_sha256: [u8; 32],
    pub transition_delegations: Vec<crate::DelegationV2>,
    pub evidence_delegations: Vec<crate::DelegationV2>,
}

/// Trusted-time facts retained for atomic receipt `/5` admission and recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptV5Validity {
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
}

/// Atomic trusted context for root-signed receipt `/5` admission.
pub trait ReceiptV5VerificationContext {
    /// Return the independently configured immutable authority-store profile.
    ///
    /// # Errors
    /// Returns an error when the authenticated backend profile is unavailable.
    fn authority_store_profile(&self) -> Result<&str, AuthorityError>;
    /// Read one authenticated durable snapshot used as the expected CAS value.
    ///
    /// # Errors
    /// Returns an error when authenticated state is unavailable.
    fn read_authority_state(&self) -> Result<crate::AuthorityStateSnapshot, AuthorityError>;
    /// Atomically admit only from the request's authenticated generation-4
    /// pre-state to its generation-5 newly-admitted state.
    ///
    /// # Errors
    /// Returns an error when trusted time, revocation, or durable recovery identity differs.
    fn admit_receipt_v5(
        &self,
        request: &crate::ReceiptV5AdmissionRequest,
    ) -> Result<crate::NewlyAdmittedReceiptV5, AuthorityError>;
    /// Perform a read-only generation-5 recovery lookup. An absent or
    /// divergent stored admission must fail without any durable mutation.
    ///
    /// # Errors
    /// Returns an error unless the full stored immutable request is equal.
    fn recover_receipt_v5(
        &self,
        request: &crate::ReceiptV5RecoveryRequest,
    ) -> Result<crate::ExistingSameReceiptV5, AuthorityError>;
}

/// Exact time, revocation, nonce, and lineage facts a durable authority backend must admit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V5AdmissionScope {
    pub envelope_sha256: [u8; 32],
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
    pub issuer_signature_profile_id: String,
    pub payload_sha256: [u8; 32],
    pub payload_schema_id: String,
    pub payload_schema_sha256: [u8; 32],
    pub issued_at: String,
    pub revocation_epoch: u64,
    pub not_before: String,
    pub expires_at: String,
    pub nonce: String,
    pub root_identity: crate::RootAuthorityIdentity5D,
    pub root_revocation_epoch: u64,
    pub destination_allowlist_generation: u64,
    pub role_scope_floors: Vec<crate::RoleScopeFloor>,
}

/// Immutable allowlist `/1` request passed to one atomic trusted backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationAllowlistAdmissionScope {
    pub allowlist_sha256: [u8; 32],
    pub unsigned_sha256: [u8; 32],
    pub generation: u64,
    pub receipt_sha256: [u8; 32],
    pub trust_config_sha256: String,
    pub trust_generation: u64,
    pub root_public_key: [u8; 32],
    pub root_principal_id: String,
    pub root_controlling_account_id: String,
    pub root_lane_id: String,
    pub root_signature_profile_id: String,
    pub root_key_id: String,
    pub root_key_epoch: u64,
    pub root_revocation_epoch: u64,
    pub policy_id: String,
    pub not_before: String,
    pub expires_at: String,
    pub role_scope_floors: Vec<crate::RoleScopeFloor>,
}

/// Atomic trusted-time and replay boundary for V5 signed envelopes.
pub trait V5EnvelopeVerificationContext {
    /// Read one authenticated durable snapshot used as the expected CAS value.
    ///
    /// # Errors
    /// Returns an error when authenticated state is unavailable.
    fn read_authority_state(&self) -> Result<crate::AuthorityStateSnapshot, AuthorityError>;
    /// Admit exactly one typed stage request, or recover only full immutable equality.
    /// The returned variant and authenticated state must describe the actual CAS result.
    ///
    /// # Errors
    /// Returns an error when trusted time, revocation, nonce, or durable identity checks fail.
    fn admit_or_recover_stage(
        &self,
        request: &crate::StageEnvelopeAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError>;
    /// Admit exactly one typed evidence request, or recover only full immutable equality.
    /// The returned variant and authenticated state must describe the actual CAS result.
    ///
    /// # Errors
    /// Returns an error for stale CAS state, freshness, floor, or replay divergence.
    fn admit_or_recover_evidence(
        &self,
        request: &crate::EvidenceEnvelopeAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError>;
}

/// Atomic trusted-time and revocation boundary for a root-signed destination allowlist.
pub trait DestinationAllowlistVerificationContext {
    /// Read one authenticated durable snapshot used as the expected CAS value.
    ///
    /// # Errors
    /// Returns an error when authenticated state is unavailable.
    fn read_authority_state(&self) -> Result<crate::AuthorityStateSnapshot, AuthorityError>;
    /// Admit an exact typed allowlist request without caller-supplied time.
    /// The returned variant and authenticated state must describe the actual CAS result.
    ///
    /// # Errors
    /// Returns an error when trusted time, revocation, or durable identity checks fail.
    fn admit_or_recover_allowlist(
        &self,
        request: &crate::DestinationAllowlistAdmissionRequest,
    ) -> Result<crate::DurableAdmission, AuthorityError>;
}
