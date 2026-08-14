//! Authenticated durable state for root promotion-bootstrap verification.

use crate::AuthorityError;

/// Authenticated root state read before a promotion-bootstrap admission attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionBootstrapVerificationState {
    /// Exact active root revocation epoch.
    pub revocation_epoch: u64,
    /// Opaque monotonically changing durable-state generation used for CAS.
    pub generation: u64,
}

/// Exact lineage and root identity scope admitted for one bootstrap digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionBootstrapAdmissionScope {
    pub(crate) authority_store_profile: String,
    pub(crate) repository_id: String,
    pub(crate) trust_config_sha256: String,
    pub(crate) predecessor_receipt_sha256: [u8; 32],
    pub(crate) root_key_id: String,
    pub(crate) root_key_epoch: u64,
    pub(crate) root_revocation_epoch: u64,
    pub(crate) root_principal_id: String,
    pub(crate) root_controlling_account_id: String,
    pub(crate) root_lane_id: String,
    pub(crate) root_signature_profile_id: String,
}
impl PromotionBootstrapAdmissionScope {
    pub(crate) fn from_bootstrap(value: &crate::PromotionBootstrapV4) -> Self {
        Self {
            authority_store_profile: value.authority_store_profile.clone(),
            repository_id: value.repository_id.clone(),
            trust_config_sha256: value.trust_config_sha256.clone(),
            predecessor_receipt_sha256: value.predecessor_receipt_sha256,
            root_key_id: value.key_id.clone(),
            root_key_epoch: value.key_epoch,
            root_revocation_epoch: value.revocation_epoch,
            root_principal_id: value.root_principal_id.clone(),
            root_controlling_account_id: value.root_controlling_account_id.clone(),
            root_lane_id: value.root_lane_id.clone(),
            root_signature_profile_id: value.root_signature_profile_id.clone(),
        }
    }
    /// Return the exact configured durable authority-store profile.
    #[must_use]
    pub fn authority_store_profile(&self) -> &str {
        &self.authority_store_profile
    }
    /// Return the exact verified repository identity.
    #[must_use]
    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }
    /// Return the exact verified V3 trust configuration digest.
    #[must_use]
    pub fn trust_config_sha256(&self) -> &str {
        &self.trust_config_sha256
    }
    /// Return the exact verified V3 reconciliation predecessor digest.
    #[must_use]
    pub const fn predecessor_receipt_sha256(&self) -> [u8; 32] {
        self.predecessor_receipt_sha256
    }
    /// Return the verified root signing-key identifier.
    #[must_use]
    pub fn root_key_id(&self) -> &str {
        &self.root_key_id
    }
    /// Return the verified root signing-key epoch.
    #[must_use]
    pub const fn root_key_epoch(&self) -> u64 {
        self.root_key_epoch
    }
    /// Return the verified root revocation epoch.
    #[must_use]
    pub const fn root_revocation_epoch(&self) -> u64 {
        self.root_revocation_epoch
    }
    /// Return the verified root principal identity.
    #[must_use]
    pub fn root_principal_id(&self) -> &str {
        &self.root_principal_id
    }
    /// Return the verified root controlling-account identity.
    #[must_use]
    pub fn root_controlling_account_id(&self) -> &str {
        &self.root_controlling_account_id
    }
    /// Return the verified root protected-lane identity.
    #[must_use]
    pub fn root_lane_id(&self) -> &str {
        &self.root_lane_id
    }
    /// Return the verified root signature-profile identity.
    #[must_use]
    pub fn root_signature_profile_id(&self) -> &str {
        &self.root_signature_profile_id
    }
}

/// Bootstrap fields that the durable backend must validate using its trusted clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionBootstrapValidity {
    pub(crate) issued_at: String,
    pub(crate) not_before: String,
    pub(crate) expires_at: String,
}
impl PromotionBootstrapValidity {
    pub(crate) fn from_bootstrap(value: &crate::PromotionBootstrapV4) -> Self {
        Self {
            issued_at: value.issued_at.clone(),
            not_before: value.not_before.clone(),
            expires_at: value.expires_at.clone(),
        }
    }
    /// Return the root issuance instant.
    #[must_use]
    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }
    /// Return the inclusive validity start.
    #[must_use]
    pub fn not_before(&self) -> &str {
        &self.not_before
    }
    /// Return the exclusive validity end.
    #[must_use]
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }
}

/// Atomic result for a root promotion-bootstrap admission request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromotionBootstrapAdmission {
    /// The backend durably admitted this exact new bootstrap under the expected generation.
    NewlyAdmitted,
    /// The exact digest and immutable scope were already admitted and may resume safely.
    ExistingSame,
}

/// Authenticated durable root state required for raw V4 bootstrap verification.
///
/// `admit_or_recover_bootstrap` is the sole freshness and admission boundary. It must obtain
/// its trusted clock, root revocation epoch, admitted digest/scope, and generation atomically.
/// For `NewlyAdmitted`, it must require `issued_at <= now`, `not_before <= now < expires_at`,
/// exact root revocation equality, and the expected generation. It may return `ExistingSame`
/// only when the exact digest and scope were already admitted and the root revocation epoch is
/// still exact; this deliberately permits crash recovery after expiry, but never after
/// revocation or for a different digest or lineage.
pub trait PromotionBootstrapVerificationContext {
    /// Return the independently configured durable authority-store profile.
    ///
    /// # Errors
    /// Returns an error when the authenticated backend profile is unavailable.
    fn authority_store_profile(&self) -> Result<&str, AuthorityError>;
    /// Read one authenticated durable root-state snapshot for the subsequent CAS.
    ///
    /// # Errors
    /// Returns an error when authenticated durable state is unavailable.
    fn read_state(&self) -> Result<PromotionBootstrapVerificationState, AuthorityError>;

    /// Atomically verify freshness/revocation and admit or recover one exact bootstrap.
    ///
    /// # Errors
    /// Returns an error for an unavailable context, a stale/revoked new bootstrap, or a CAS,
    /// digest, scope, or lineage conflict.
    fn admit_or_recover_bootstrap(
        &self,
        expected: &PromotionBootstrapVerificationState,
        receipt_sha256: [u8; 32],
        scope: &PromotionBootstrapAdmissionScope,
        validity: &PromotionBootstrapValidity,
    ) -> Result<PromotionBootstrapAdmission, AuthorityError>;
}
