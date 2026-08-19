//! Fail-closed authority engine for post-RC0 release promotion.
#[cfg(all(test, feature = "fixture-only"))]
extern crate self as runne_release_authority;
#[cfg(any(test, feature = "fixture-only"))]
mod admission;
#[cfg(any(test, feature = "fixture-only"))]
mod admission_facts;
mod candidate;
mod effect;
mod error;
mod identity_separation;
#[cfg(any(test, feature = "fixture-only"))]
pub(crate) mod native_evidence;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_admission;
include!("publication_effect_modules.rs");
#[cfg(any(test, feature = "fixture-only"))]
mod rc2_effect_lease;
#[cfg(any(test, feature = "fixture-only"))]
pub(crate) mod rc2_evidence_common;
mod rc3_v2_admission;
#[cfg(any(test, feature = "fixture-only"))]
mod signed_bundle;
#[cfg(any(test, feature = "fixture-only"))]
mod signed_bundle_closure;
#[cfg(any(test, feature = "fixture-only"))]
mod signed_bundle_lease;
#[cfg(any(test, feature = "fixture-only"))]
pub(crate) mod signing_effect_evidence;
#[cfg(any(test, feature = "fixture-only"))]
mod signing_review_evidence;
mod stage_inspection;
mod store;
#[cfg(any(test, feature = "fixture-only"))]
mod store_command;
#[cfg(any(test, feature = "fixture-only"))]
mod store_durable;
#[cfg(any(test, feature = "fixture-only"))]
mod store_durable_authority;
#[cfg(any(test, feature = "fixture-only"))]
mod store_durable_authority_ack;
#[cfg(any(test, feature = "fixture-only"))]
mod store_durable_authority_effect;
#[cfg(any(test, feature = "fixture-only"))]
mod store_durable_authority_trust;
#[cfg(any(test, feature = "fixture-only"))]
mod store_durable_file;
#[cfg(any(test, feature = "fixture-only"))]
mod store_durable_lease;
#[cfg(any(test, feature = "fixture-only"))]
mod store_durable_publication_binding;
#[cfg(any(test, feature = "fixture-only"))]
#[cfg(any(test, feature = "fixture-only"))]
mod store_durable_trust;
#[cfg(any(test, feature = "fixture-only"))]
pub(crate) mod store_durable_wire;
#[cfg(any(test, feature = "fixture-only"))]
mod store_effect;
#[cfg(any(test, feature = "fixture-only"))]
mod store_machine;
#[cfg(any(test, feature = "fixture-only"))]
mod store_machine_rc2;
#[cfg(any(test, feature = "fixture-only"))]
mod store_memory;
#[cfg(any(test, feature = "fixture-only"))]
mod store_publication_effect;
#[cfg(all(test, feature = "fixture-only"))]
mod store_publication_effect_fixture;
#[cfg(all(test, feature = "fixture-only"))]
mod store_publication_effect_fixture_crash_tests;
#[cfg(all(test, feature = "fixture-only"))]
mod store_publication_effect_fixture_tests;
#[cfg(any(test, feature = "fixture-only"))]
mod store_rc2_effect_evidence;
#[cfg(any(test, feature = "fixture-only"))]
mod store_rc2_effect_lease;
#[cfg(any(test, feature = "fixture-only"))]
pub(crate) mod store_rc2_evidence_trust;
#[cfg(any(test, feature = "fixture-only"))]
mod store_receipt;
#[cfg(any(test, feature = "fixture-only"))]
mod store_snapshot;
#[cfg(any(test, feature = "fixture-only"))]
mod store_stage_claim;
#[cfg(any(test, feature = "fixture-only"))]
mod store_stage_context;
#[cfg(any(test, feature = "fixture-only"))]
mod store_stage_reservation;
#[cfg(any(test, feature = "fixture-only"))]
mod store_stage_trust;
#[cfg(any(test, feature = "fixture-only"))]
mod store_transition;
#[cfg(any(test, feature = "fixture-only"))]
mod store_transition_reserve;
#[cfg(any(test, feature = "fixture-only"))]
mod threshold_context;
#[cfg(any(test, feature = "fixture-only"))]
mod threshold_context_predecessor;
#[cfg(any(test, feature = "fixture-only"))]
mod threshold_fixture;
#[cfg(any(test, feature = "fixture-only"))]
mod threshold_fixture_wire;
#[cfg(any(test, feature = "fixture-only"))]
mod threshold_metadata_evidence;
#[cfg(any(test, feature = "fixture-only"))]
mod threshold_proof;
#[cfg(any(test, feature = "fixture-only"))]
mod threshold_scope;
#[cfg(any(test, feature = "fixture-only"))]
mod threshold_signatures;
#[cfg(any(test, feature = "fixture-only"))]
mod threshold_target_binding;
#[cfg(any(test, feature = "fixture-only"))]
mod update_metadata_evidence;
pub(crate) mod wire;
#[cfg(any(test, feature = "fixture-only"))]
pub use admission::FixtureAdmission;
pub use candidate::{CandidateBinding, Digest};
pub use effect::{
    EffectError, EffectSnapshot, EffectState, EffectTransition, InertEffectTransitionValidator,
    PublicationEffectTransitionValidator,
};
#[cfg(any(test, feature = "fixture-only"))]
pub use effect::{
    EffectRequestFixture, FixturePublicationEffectMachine, PublicationAuthorizedBinding,
    PublicationEffectRequest,
};
pub use error::AuthorityError;
pub use identity_separation::{verify_rc2_operation_separation, verify_rc3_operation_separation};
#[cfg(any(test, feature = "fixture-only"))]
pub use native_evidence::FixtureVerifiedNativeEvidence;
#[cfg(any(test, feature = "fixture-only"))]
pub use publication_admission::FixturePublicationBundle;
#[cfg(any(test, feature = "fixture-only"))]
pub(crate) use publication_effect_ledger::FixturePublicationEffectLedger;
#[cfg(any(test, feature = "fixture-only"))]
pub use rc2_effect_lease::{
    EffectLeaseError, FixtureRc2SigningDispatchLease, FixtureRc2SigningDispatchLeases,
    Rc2SigningBackendReadbackFixture, Rc2SigningEffectClaim, Rc2SigningEffectLeaseState,
};
#[cfg(any(test, feature = "fixture-only"))]
pub(crate) use rc2_effect_lease::{FixtureRc2EffectLeaseLedger, FixtureRc2SigningAuthorization};
#[cfg(any(test, feature = "fixture-only"))]
pub use rc2_evidence_common::{
    FixtureEvidenceKeyRegistration, FixtureEvidenceTrustState, RawRc2Evidence,
};
pub use rc3_v2_admission::inspect_rc3_v2_leaf;
#[cfg(any(test, feature = "fixture-only"))]
pub use signed_bundle::FixturePrevalidatedSignedBundle;
#[cfg(any(test, feature = "fixture-only"))]
pub use signing_effect_evidence::{FixtureInFlightSigningEffect, FixtureVerifiedSigningEffect};
#[cfg(any(test, feature = "fixture-only"))]
pub use signing_review_evidence::FixtureVerifiedSigningReview;
pub use stage_inspection::{VerifiedStageTransition, inspect_verified_stage_envelope};
#[cfg(any(test, feature = "fixture-only"))]
pub use store::InMemoryPromotionStore;
#[cfg(any(test, feature = "fixture-only"))]
pub use store::{
    CommandId, Mutation, PromotionId, PromotionState, PromotionStore, RawStageTransitionRequest,
    StageTransitionStore, StageTrustFixture, TransactionOutcome,
};
pub use store::{ProductionAuthorityStatus, UnprovisionedPromotionStore};
#[cfg(any(test, feature = "fixture-only"))]
pub use store_durable::DurableFixturePromotionStore;
#[cfg(any(test, feature = "fixture-only"))]
pub use store_durable_authority::DurableFixturePromotionAuthority;
#[cfg(any(test, feature = "fixture-only"))]
pub use store_receipt::SigningAuthorizedReceipt;
#[cfg(any(test, feature = "fixture-only"))]
pub use store_snapshot::PromotionStateSnapshot;
#[cfg(any(test, feature = "fixture-only"))]
pub use threshold_context::{
    AuthenticatedThresholdTransition, ThresholdAdmission, ThresholdAdmissionRequest,
    ThresholdVerificationContext, ThresholdVerificationState,
};
#[cfg(any(test, feature = "fixture-only"))]
pub use threshold_fixture::{DurableFixtureThresholdContext, ThresholdFixtureStoreBinding};
#[cfg(any(test, feature = "fixture-only"))]
pub use threshold_proof::{DurableThresholdProof, admit_prevalidated_signed_bundle};
#[cfg(any(test, feature = "fixture-only"))]
pub use threshold_scope::{
    PendingThresholdAck, ThresholdAckProof, ThresholdAckRequest, ThresholdAdmissionScope,
};
#[cfg(any(test, feature = "fixture-only"))]
pub use update_metadata_evidence::FixtureVerifiedUpdateMetadataIssuance;
pub use wire::{CanonicalPayloadKind, InspectedCanonicalPayload};
/// Opaque release-stage input coupled to a cryptographically verified owner envelope.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedStagePayload {
    pub(crate) payload: InspectedCanonicalPayload,
    pub(crate) envelope_payload_sha256: [u8; 32],
    pub(crate) issuer: StageIssuerIdentity,
    pub(crate) root: StageIssuerIdentity,
    pub(crate) bootstrap: Digest,
}
/// Five-dimensional issuer identity copied from a verified owner handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageIssuerIdentity {
    principal: String,
    account: String,
    lane: String,
    key: String,
    signature_profile: String,
}
impl StageIssuerIdentity {
    /// Return the verified issuer principal identifier.
    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.principal
    }
    /// Return the verified issuer account identifier.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account
    }
    /// Return the verified issuer lane identifier.
    #[must_use]
    pub fn lane_id(&self) -> &str {
        &self.lane
    }
    /// Return the verified issuer key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key
    }
    /// Return the verified issuer signature-profile identifier.
    #[must_use]
    pub fn signature_profile_id(&self) -> &str {
        &self.signature_profile
    }
}
#[cfg(any(test, feature = "fixture-only"))]
impl StageIssuerIdentity {
    pub(crate) const fn durable(
        principal: String,
        account: String,
        lane: String,
        key: String,
        signature_profile: String,
    ) -> Self {
        Self {
            principal,
            account,
            lane,
            key,
            signature_profile,
        }
    }
}
impl VerifiedStagePayload {
    /// Return the exact stage contract kind verified by the owner envelope.
    #[must_use]
    pub const fn kind(&self) -> CanonicalPayloadKind {
        self.payload.kind()
    }
    /// Return the raw payload SHA-256 verified inside the owner envelope.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.envelope_payload_sha256
    }
    /// Return the five-dimensional verified delegated issuer identity.
    #[must_use]
    pub const fn issuer(&self) -> &StageIssuerIdentity {
        &self.issuer
    }
    /// Return the root identity verified through the bound bootstrap receipt.
    #[must_use]
    pub const fn root(&self) -> &StageIssuerIdentity {
        &self.root
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) const fn bootstrap(&self) -> Digest {
        self.bootstrap
    }
    pub(crate) const fn inspected(&self) -> &InspectedCanonicalPayload {
        &self.payload
    }
}

/// Minimal immutable stage facts retained by the promotion store after consuming a handle.
#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone)]
pub(crate) struct StoredStage {
    pub(crate) sha256: [u8; 32],
    pub(crate) issuer: StageIssuerIdentity,
    pub(crate) root: StageIssuerIdentity,
    pub(crate) bootstrap: Digest,
}
#[cfg(any(test, feature = "fixture-only"))]
impl VerifiedStagePayload {
    pub(crate) fn into_stored(self) -> StoredStage {
        StoredStage {
            sha256: self.envelope_payload_sha256,
            issuer: self.issuer,
            root: self.root,
            bootstrap: self.bootstrap,
        }
    }
}
