//! Promotion-bootstrap receipt model and canonical unsigned bytes.

use serde::Deserialize;

use crate::{AuthorityError, Document, GitSubject, SchemaDigest};

pub use crate::receipt_v4_canonical::{
    canonical_checked_in_promotion_bootstrap, canonical_unsigned_promotion_bootstrap,
};

/// Fixed schema identifier for promotion bootstrap receipts.
pub const RECEIPT_SCHEMA_V4: &str = "runne.project-owner.authority-receipt/4";
/// Fixed purpose for promotion bootstrap receipts.
pub const PURPOSE_V4: &str = "POST_RC0_PROMOTION_AUTHORITY_BOOTSTRAP";
/// Fixed promotion bootstrap profile.
pub const PROFILE_V4: &str = "runne.project-owner.post-rc0-promotion/1";
pub(crate) const ROLES: [&str; 3] = [
    "RC1_QUALIFICATION_AUTHORIZER",
    "RC2_SIGNING_AUTHORIZER",
    "RC3_PUBLICATION_AUTHORIZER",
];

/// One separately controlled promotion stage authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DelegationV1 {
    /// Fixed stage authorization role.
    pub role: String,
    /// Immutable principal identity.
    pub principal_id: String,
    /// Controlling account identity.
    pub controlling_account_id: String,
    /// Protected execution lane identity.
    pub lane_id: String,
    /// SHA-256 identifier derived from the stage public key.
    pub key_id: String,
    /// Ed25519 verification key.
    pub public_key: [u8; 32],
    /// Delegated key epoch.
    pub key_epoch: u64,
    /// Exact signature-profile identity.
    pub signature_profile_id: String,
    /// Inclusive authorization start time.
    pub not_before: String,
    /// Exclusive authorization end time.
    pub expires_at: String,
    /// Current revocation epoch required by stage envelopes.
    pub revocation_epoch: u64,
    /// Exact payload schemas permitted for this role.
    pub allowed_payload_schema_ids: Vec<String>,
}

/// Unsigned root-signed promotion authority bootstrap.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PromotionBootstrapV4 {
    /// Receipt schema identifier.
    pub schema_version: String,
    /// Bound repository identity.
    pub repository_id: String,
    /// Root project-owner role.
    pub role: String,
    /// Fixed receipt purpose.
    pub purpose: String,
    /// Fixed profile identifier.
    pub profile: String,
    /// Raw verified reconciliation receipt digest.
    pub predecessor_receipt_sha256: [u8; 32],
    /// Exact platform-qualified-subject v2 digest.
    pub platform_qualified_subject_sha256: [u8; 32],
    /// Exact platform matrix v3 digest.
    pub platform_matrix_sha256: [u8; 32],
    /// Exact promotion-policy digest.
    pub promotion_policy_sha256: [u8; 32],
    /// Immutable promotion-policy revision.
    pub promotion_policy_revision: String,
    /// External authority-store profile identity.
    pub authority_store_profile: String,
    /// Immutable root principal identity, distinct from every delegation.
    pub root_principal_id: String,
    /// Root controlling account identity, distinct from every delegation.
    pub root_controlling_account_id: String,
    /// Root protected execution lane, distinct from every delegation.
    pub root_lane_id: String,
    /// Root signature-profile identity, distinct from every delegation.
    pub root_signature_profile_id: String,
    /// Root issuance time.
    pub issued_at: String,
    /// Bootstrap validity start.
    pub not_before: String,
    /// Bootstrap validity end.
    pub expires_at: String,
    /// Root revocation epoch.
    pub revocation_epoch: u64,
    /// Ordered RC1, RC2, RC3 delegations.
    pub delegations: Vec<DelegationV1>,
    /// Immutable source subject.
    pub subject: GitSubject,
    /// Exact regular document bindings.
    pub documents: Vec<Document>,
    /// Canonical V3 trust configuration digest.
    pub trust_config_sha256: String,
    /// Root key identifier.
    pub key_id: String,
    /// Root key epoch.
    pub key_epoch: u64,
}

/// A root-signed promotion bootstrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPromotionBootstrapV4 {
    /// SHA-256 of canonical checked-in bytes.
    pub project_owner_authority_receipt_sha256: [u8; 32],
    /// Canonical unsigned fields.
    pub unsigned: PromotionBootstrapV4,
    /// Root detached Ed25519 signature.
    pub signature: [u8; 64],
}

/// Opaque evidence that raw promotion bootstrap verification completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPromotionBootstrap {
    receipt_sha256: [u8; 32],
    subject: GitSubject,
    bindings: PromotionBootstrapBindings,
    delegations: Vec<DelegationV1>,
    root_public_key: [u8; 32],
    root_identity: crate::VerifiedStageIssuer,
    validity: crate::PromotionBootstrapValidity,
    admission_scope: crate::PromotionBootstrapAdmissionScope,
}

/// Immutable RC0 qualification bindings retained from a verified V4 bootstrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionBootstrapBindings {
    subject_sha256: [u8; 32],
    matrix_sha256: [u8; 32],
    policy_sha256: [u8; 32],
    policy_revision: String,
}

impl PromotionBootstrapBindings {
    pub(crate) fn from_bootstrap(value: &PromotionBootstrapV4) -> Self {
        Self {
            subject_sha256: value.platform_qualified_subject_sha256,
            matrix_sha256: value.platform_matrix_sha256,
            policy_sha256: value.promotion_policy_sha256,
            policy_revision: value.promotion_policy_revision.clone(),
        }
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
}

impl VerifiedPromotionBootstrap {
    /// Return the verified canonical bootstrap digest.
    #[must_use]
    pub const fn receipt_sha256(&self) -> [u8; 32] {
        self.receipt_sha256
    }

    /// Return the exact immutable Git subject authenticated by this bootstrap.
    #[must_use]
    pub const fn subject(&self) -> &GitSubject {
        &self.subject
    }

    /// Return immutable qualification bindings authenticated by this bootstrap.
    #[must_use]
    pub const fn bindings(&self) -> &PromotionBootstrapBindings {
        &self.bindings
    }

    pub(crate) fn delegation(&self, role: &str) -> Option<&DelegationV1> {
        self.delegations.iter().find(|item| item.role == role)
    }
    pub(crate) const fn root_public_key(&self) -> [u8; 32] {
        self.root_public_key
    }
    /// Return the verified five-dimensional root identity.
    #[must_use]
    pub const fn root_identity(&self) -> &crate::VerifiedStageIssuer {
        &self.root_identity
    }
    /// Return the retained verified root-bootstrap validity window.
    #[must_use]
    pub const fn validity(&self) -> &crate::PromotionBootstrapValidity {
        &self.validity
    }
    /// Return the retained immutable admission scope for this bootstrap.
    #[must_use]
    pub const fn admission_scope(&self) -> &crate::PromotionBootstrapAdmissionScope {
        &self.admission_scope
    }
}

#[cfg(test)]
pub(crate) const fn verified_bootstrap(
    digest: [u8; 32],
    delegations: Vec<DelegationV1>,
    root_public_key: [u8; 32],
    subject: GitSubject,
    trust_config_sha256: String,
) -> VerifiedPromotionBootstrap {
    verified_bootstrap_with_root(
        digest,
        delegations,
        root_public_key,
        subject,
        crate::VerifiedStageIssuer {
            principal: String::new(),
            account: String::new(),
            lane: String::new(),
            key: String::new(),
            signature_profile: String::new(),
        },
        crate::PromotionBootstrapValidity {
            issued_at: String::new(),
            not_before: String::new(),
            expires_at: String::new(),
        },
        crate::PromotionBootstrapAdmissionScope {
            authority_store_profile: String::new(),
            repository_id: String::new(),
            trust_config_sha256,
            predecessor_receipt_sha256: [0; 32],
            root_key_id: String::new(),
            root_key_epoch: 0,
            root_revocation_epoch: 0,
            root_principal_id: String::new(),
            root_controlling_account_id: String::new(),
            root_lane_id: String::new(),
            root_signature_profile_id: String::new(),
        },
        PromotionBootstrapBindings {
            subject_sha256: [0; 32],
            matrix_sha256: [0; 32],
            policy_sha256: [0; 32],
            policy_revision: String::new(),
        },
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "test-visible bootstrap constructor needs full lineage scope"
)]
pub(crate) const fn verified_bootstrap_with_root(
    digest: [u8; 32],
    delegations: Vec<DelegationV1>,
    root_public_key: [u8; 32],
    subject: GitSubject,
    root_identity: crate::VerifiedStageIssuer,
    validity: crate::PromotionBootstrapValidity,
    admission_scope: crate::PromotionBootstrapAdmissionScope,
    bindings: PromotionBootstrapBindings,
) -> VerifiedPromotionBootstrap {
    VerifiedPromotionBootstrap {
        receipt_sha256: digest,
        subject,
        bindings,
        delegations,
        root_public_key,
        root_identity,
        validity,
        admission_scope,
    }
}

/// Return promotion schema pins only after the release-contract owner finalizes them.
///
/// # Errors
/// Returns the fail-closed V3 pin-finalization error until the immutable union is available.
pub fn promotion_schema_pins() -> Result<Vec<SchemaDigest>, AuthorityError> {
    crate::v3_trust_schema_digests()
}

#[cfg(test)]
pub(crate) const fn test_empty_subject() -> GitSubject {
    GitSubject {
        object_format: String::new(),
        commit_oid: String::new(),
        tree_oid: String::new(),
    }
}
