//! Sealed, non-authorizing lineage views for pure V4-to-V5 composition.

use crate::receipt_v5::ReceiptV5Bindings;
use crate::{
    DelegationV2, GitSubject, PrevalidatedPromotionAuthorityReceiptV5,
    PrevalidatedPromotionBootstrapV4, PromotionBootstrapBindings,
    VerifiedPromotionAuthorityReceiptV5, VerifiedPromotionBootstrap, VerifiedStageIssuer,
};

#[doc(hidden)]
pub struct V4LineageView<'a> {
    pub receipt_sha256: [u8; 32],
    pub subject: &'a GitSubject,
    pub bindings: &'a PromotionBootstrapBindings,
    pub admission_scope: &'a crate::PromotionBootstrapAdmissionScope,
}

#[doc(hidden)]
pub struct V5LineageView<'a> {
    pub receipt_sha256: [u8; 32],
    pub transition_delegations: &'a [DelegationV2],
    pub evidence_delegations: &'a [DelegationV2],
    pub root_public_key: [u8; 32],
    pub root_identity: VerifiedStageIssuer,
    pub root_revocation_epoch: u64,
    pub bindings: ReceiptV5Bindings,
}

mod sealed {
    use super::{V4LineageView, V5LineageView};

    pub trait V4Source {
        fn v4_lineage(&self) -> V4LineageView<'_>;
    }
    pub trait V5Source {
        fn v5_lineage(&self) -> V5LineageView<'_>;
    }
}

/// A sealed, non-authorizing source of cryptographically validated V4 lineage.
pub trait PromotionBootstrapV4Lineage: sealed::V4Source {}
/// A sealed, non-authorizing source of cryptographically validated V5 lineage.
pub trait PromotionAuthorityReceiptV5Lineage: sealed::V5Source {}

impl sealed::V4Source for PrevalidatedPromotionBootstrapV4 {
    fn v4_lineage(&self) -> V4LineageView<'_> {
        V4LineageView {
            receipt_sha256: self.receipt.project_owner_authority_receipt_sha256,
            subject: &self.receipt.unsigned.subject,
            bindings: &self.bindings,
            admission_scope: &self.scope,
        }
    }
}
impl PromotionBootstrapV4Lineage for PrevalidatedPromotionBootstrapV4 {}

impl sealed::V4Source for VerifiedPromotionBootstrap {
    fn v4_lineage(&self) -> V4LineageView<'_> {
        V4LineageView {
            receipt_sha256: self.receipt_sha256(),
            subject: self.subject(),
            bindings: self.bindings(),
            admission_scope: self.admission_scope(),
        }
    }
}
impl PromotionBootstrapV4Lineage for VerifiedPromotionBootstrap {}

impl sealed::V5Source for PrevalidatedPromotionAuthorityReceiptV5 {
    fn v5_lineage(&self) -> V5LineageView<'_> {
        V5LineageView::from_parts(self.receipt_sha256, &self.unsigned, self.root_public_key)
    }
}
impl PromotionAuthorityReceiptV5Lineage for PrevalidatedPromotionAuthorityReceiptV5 {}

impl sealed::V5Source for VerifiedPromotionAuthorityReceiptV5 {
    fn v5_lineage(&self) -> V5LineageView<'_> {
        V5LineageView {
            receipt_sha256: self.receipt_sha256(),
            transition_delegations: &self.transition_delegations,
            evidence_delegations: &self.evidence_delegations,
            root_public_key: self.root_public_key(),
            root_identity: self.root_identity.clone(),
            root_revocation_epoch: self.root_revocation_epoch,
            bindings: self.bindings().clone(),
        }
    }
}
impl PromotionAuthorityReceiptV5Lineage for VerifiedPromotionAuthorityReceiptV5 {}

impl<'a> V5LineageView<'a> {
    pub(crate) fn durable_root(&self) -> crate::RootAuthorityIdentity5D {
        crate::RootAuthorityIdentity5D {
            principal_id: self.root_identity.principal_id().into(),
            controlling_account_id: self.root_identity.account_id().into(),
            lane_id: self.root_identity.lane_id().into(),
            key_id: self.root_identity.key_id().into(),
            signature_profile_id: self.root_identity.signature_profile_id().into(),
            public_key: self.root_public_key,
            key_epoch: self.bindings.trust_generation(),
        }
    }
    pub(crate) fn role_floors(&self) -> Vec<crate::RoleScopeFloor> {
        crate::v5_state_validation::floors(self.transition_delegations, self.evidence_delegations)
    }
    fn from_parts(
        receipt_sha256: [u8; 32],
        value: &'a crate::PromotionAuthorityReceiptV5,
        root_public_key: [u8; 32],
    ) -> Self {
        Self {
            receipt_sha256,
            transition_delegations: &value.transition_delegations,
            evidence_delegations: &value.evidence_delegations,
            root_public_key,
            root_identity: VerifiedStageIssuer {
                principal: value.root_principal_id.clone(),
                account: value.root_controlling_account_id.clone(),
                lane: value.root_lane_id.clone(),
                key: value.key_id.clone(),
                signature_profile: value.root_signature_profile_id.clone(),
            },
            root_revocation_epoch: value.revocation_epoch,
            bindings: ReceiptV5Bindings::from_receipt(value),
        }
    }
}

pub fn v4_lineage(value: &impl PromotionBootstrapV4Lineage) -> V4LineageView<'_> {
    sealed::V4Source::v4_lineage(value)
}
pub fn v5_lineage(value: &impl PromotionAuthorityReceiptV5Lineage) -> V5LineageView<'_> {
    sealed::V5Source::v5_lineage(value)
}
