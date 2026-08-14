//! V5 active promotion authority receipt model.

use serde::{Deserialize, Serialize};

use crate::{AuthorityError, GitSubject};

/// Fixed schema identifier for the active, versioned promotion authority receipt.
pub const RECEIPT_SCHEMA_V5: &str = "gocode.project-owner.authority-receipt/5";
/// Fixed purpose bound to the V4 root and V5 authority closure.
pub const PURPOSE_V5: &str = "POST_RC0_VERSIONED_PROMOTION_AUTHORITY";
/// Fixed V5 release authority profile.
pub const PROFILE_V5: &str = "gocode.project-owner.post-rc0-promotion/2";
/// Ordered, closed transition authorization roles.
pub const V5_TRANSITION_ROLES: [&str; 3] = [
    "RC1_QUALIFICATION_AUTHORIZER",
    "RC2_SIGNING_AUTHORIZER",
    "RC3_PUBLICATION_AUTHORIZER",
];
/// Ordered, closed evidence role and scope lookup keys.
pub const V5_EVIDENCE_ROLE_SCOPES: [(&str, &str); 5] = [
    ("RC2_NATIVE_EVIDENCE", "linux"),
    ("RC2_NATIVE_EVIDENCE", "windows"),
    ("RC2_SIGNING_REVIEWER", "signing-review"),
    ("RC2_UPDATE_ISSUER", "update-issuer"),
    ("RC3_FINAL_REVIEWER", "final-review"),
];

/// One independent transition or evidence signing delegation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationV2 {
    pub role: String,
    pub scope: String,
    pub principal_id: String,
    pub controlling_account_id: String,
    pub lane_id: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub key_epoch: u64,
    pub signature_profile_id: String,
    pub not_before: String,
    pub expires_at: String,
    pub revocation_epoch: u64,
    pub allowed_payload_schema_ids: Vec<String>,
}

/// Root-signed V5 receipt. It remains non-active until V4 schema pins finalize.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionAuthorityReceiptV5 {
    pub schema_version: String,
    pub repository_id: String,
    pub role: String,
    pub purpose: String,
    pub profile: String,
    pub predecessor_receipt_sha256: [u8; 32],
    pub trust_config_sha256: String,
    pub trust_generation: u64,
    pub platform_qualified_subject_sha256: [u8; 32],
    pub platform_matrix_sha256: [u8; 32],
    pub production_security_review_sha256: [u8; 32],
    pub promotion_policy_sha256: [u8; 32],
    pub promotion_policy_revision: String,
    pub adr_0029_sha256: [u8; 32],
    pub post_rc0_program_sha256: [u8; 32],
    pub destination_allowlist_sha256: [u8; 32],
    pub destination_allowlist_generation: u64,
    pub authority_store_profile: String,
    pub root_principal_id: String,
    pub root_controlling_account_id: String,
    pub root_lane_id: String,
    pub root_signature_profile_id: String,
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
    pub revocation_epoch: u64,
    pub transition_delegations: Vec<DelegationV2>,
    pub evidence_delegations: Vec<DelegationV2>,
    pub subject: GitSubject,
    pub key_id: String,
    pub key_epoch: u64,
}

/// A root-signed V5 receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPromotionAuthorityReceiptV5 {
    pub project_owner_authority_receipt_sha256: [u8; 32],
    pub unsigned: PromotionAuthorityReceiptV5,
    pub signature: [u8; 64],
}

/// Opaque result of raw V5 verification.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedPromotionAuthorityReceiptV5 {
    receipt_sha256: [u8; 32],
    pub(crate) transition_delegations: Vec<DelegationV2>,
    pub(crate) evidence_delegations: Vec<DelegationV2>,
    root_public_key: [u8; 32],
    pub(crate) root_identity: crate::VerifiedStageIssuer,
    pub(crate) root_revocation_epoch: u64,
    bindings: ReceiptV5Bindings,
}

/// Immutable V5 bindings consumed by stage and evidence envelope verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptV5Bindings {
    pub(crate) trust_config_sha256: String,
    pub(crate) trust_generation: u64,
    pub(crate) subject_sha256: [u8; 32],
    pub(crate) matrix_sha256: [u8; 32],
    pub(crate) policy_sha256: [u8; 32],
    pub(crate) policy_revision: String,
    pub(crate) destination_allowlist_sha256: [u8; 32],
    pub(crate) destination_allowlist_generation: u64,
    pub(crate) production_security_review_sha256: [u8; 32],
    pub(crate) subject: GitSubject,
}

/// Independently verified instance bindings required before receipt `/5` admission.
///
/// This value intentionally has no public constructor: callers must obtain it from
/// their document-verification boundary rather than reuse a trust-schema digest.
#[derive(Debug, Eq, PartialEq)]
pub struct ExpectedReceiptV5Bindings {
    pub(crate) production_security_review_sha256: [u8; 32],
    pub(crate) subject: GitSubject,
    pub(crate) destination_allowlist_unsigned_sha256: [u8; 32],
    pub(crate) destination_allowlist_generation: u64,
}

/// Cryptographically complete, non-authorizing receipt `/5` validation result.
///
/// ```compile_fail
/// fn authorize(value: gocode_project_owner_authority::PrevalidatedPromotionAuthorityReceiptV5) {
///     let _ = value.transition_delegation("RC3_PUBLICATION_AUTHORIZER");
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct PrevalidatedPromotionAuthorityReceiptV5 {
    pub(crate) receipt_sha256: [u8; 32],
    pub(crate) unsigned: PromotionAuthorityReceiptV5,
    pub(crate) root_public_key: [u8; 32],
}
impl ExpectedReceiptV5Bindings {
    #[cfg(test)]
    pub(crate) const fn test_only(
        production_security_review_sha256: [u8; 32],
        subject: GitSubject,
        destination_allowlist_unsigned_sha256: [u8; 32],
        destination_allowlist_generation: u64,
    ) -> Self {
        Self {
            production_security_review_sha256,
            subject,
            destination_allowlist_unsigned_sha256,
            destination_allowlist_generation,
        }
    }
}
impl ReceiptV5Bindings {
    pub(crate) fn from_receipt(value: &PromotionAuthorityReceiptV5) -> Self {
        Self {
            trust_config_sha256: value.trust_config_sha256.clone(),
            trust_generation: value.trust_generation,
            subject_sha256: value.platform_qualified_subject_sha256,
            matrix_sha256: value.platform_matrix_sha256,
            policy_sha256: value.promotion_policy_sha256,
            policy_revision: value.promotion_policy_revision.clone(),
            destination_allowlist_sha256: value.destination_allowlist_sha256,
            destination_allowlist_generation: value.destination_allowlist_generation,
            production_security_review_sha256: value.production_security_review_sha256,
            subject: value.subject.clone(),
        }
    }
    #[must_use]
    pub fn trust_config_sha256(&self) -> &str {
        &self.trust_config_sha256
    }
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }
    #[must_use]
    pub const fn subject_sha256(&self) -> [u8; 32] {
        self.subject_sha256
    }
    #[must_use]
    pub const fn matrix_sha256(&self) -> [u8; 32] {
        self.matrix_sha256
    }
    #[must_use]
    pub const fn policy_sha256(&self) -> [u8; 32] {
        self.policy_sha256
    }
    #[must_use]
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }
    #[must_use]
    pub const fn destination_allowlist_sha256(&self) -> [u8; 32] {
        self.destination_allowlist_sha256
    }
    #[must_use]
    pub const fn destination_allowlist_generation(&self) -> u64 {
        self.destination_allowlist_generation
    }
    #[must_use]
    pub const fn production_security_review_sha256(&self) -> [u8; 32] {
        self.production_security_review_sha256
    }
    #[must_use]
    pub const fn subject(&self) -> &GitSubject {
        &self.subject
    }
}

impl VerifiedPromotionAuthorityReceiptV5 {
    /// Return the exact signed V5 receipt digest.
    #[must_use]
    pub const fn receipt_sha256(&self) -> [u8; 32] {
        self.receipt_sha256
    }
    /// Look up one exact transition authorization delegation.
    #[must_use]
    pub fn transition_delegation(&self, role: &str) -> Option<&DelegationV2> {
        self.transition_delegations
            .iter()
            .find(|item| item.role == role)
    }
    /// Look up one exact evidence delegation by its role and scoped label.
    #[must_use]
    pub fn evidence_delegation(&self, role: &str, scope: &str) -> Option<&DelegationV2> {
        self.evidence_delegations
            .iter()
            .find(|item| item.role == role && item.scope == scope)
    }
    /// Return the verified V4 root verification key.
    #[must_use]
    pub const fn root_public_key(&self) -> [u8; 32] {
        self.root_public_key
    }
    /// Return immutable V5 trust, candidate, policy, and allowlist bindings.
    #[must_use]
    pub const fn bindings(&self) -> &ReceiptV5Bindings {
        &self.bindings
    }
}

/// Compatibility name for consumers that model receipt `/5` as the successor bootstrap.
pub type VerifiedPromotionBootstrapV5 = VerifiedPromotionAuthorityReceiptV5;

pub const fn verified_receipt_v5(
    receipt_sha256: [u8; 32],
    transition_delegations: Vec<DelegationV2>,
    evidence_delegations: Vec<DelegationV2>,
    root_public_key: [u8; 32],
    root_identity: crate::VerifiedStageIssuer,
    root_revocation_epoch: u64,
    bindings: ReceiptV5Bindings,
) -> VerifiedPromotionAuthorityReceiptV5 {
    VerifiedPromotionAuthorityReceiptV5 {
        receipt_sha256,
        transition_delegations,
        evidence_delegations,
        root_public_key,
        root_identity,
        root_revocation_epoch,
        bindings,
    }
}

/// Return a fail-closed result until the V4 trust pin union is finalized.
///
/// # Errors
/// Returns the explicit fail-closed V4 pending-pins error until leaf schemas stabilize.
pub fn v5_receipt_schema_pins() -> Result<Vec<crate::SchemaDigest>, AuthorityError> {
    crate::v4_trust_schema_digests()
}
