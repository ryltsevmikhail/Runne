//! Store-owned raw RC2 evidence verification and final bundle closure.
#![allow(clippy::missing_errors_doc)] // Fixture promotion-store evidence boundary.

use crate::native_evidence::{replay_native_evidence, verify_native_evidence_closing_lease};
use crate::rc2_effect_lease::StoredRawEvidence;
use crate::signing_effect_evidence::{
    replay_signing_effect_claim, verify_signing_effect_claim_with_lease,
};
use crate::signing_review_evidence::verify_signing_review;
use crate::update_metadata_evidence::verify_update_metadata_issuance;
use crate::{
    AuthorityError, FixtureInFlightSigningEffect, FixturePrevalidatedSignedBundle,
    FixtureRc2SigningDispatchLease, FixtureVerifiedNativeEvidence, FixtureVerifiedSigningEffect,
    FixtureVerifiedSigningReview, FixtureVerifiedUpdateMetadataIssuance, InMemoryPromotionStore,
    InspectedCanonicalPayload, PromotionId, PromotionState, RawRc2Evidence,
};

impl InMemoryPromotionStore {
    pub fn verify_rc2_signing_effect_with_lease(
        &mut self,
        id: &PromotionId,
        evidence: RawRc2Evidence,
        authorization: &InspectedCanonicalPayload,
        lease: FixtureRc2SigningDispatchLease,
    ) -> Result<FixtureInFlightSigningEffect, AuthorityError> {
        let retained = StoredRawEvidence {
            raw: evidence.raw.clone(),
            signature: evidence.signature,
        };
        let cache = (
            lease.namespace().to_owned(),
            lease.authorization(),
            lease.generation(),
            lease.slot().to_owned(),
        );
        let record = self
            .entries
            .get(id)
            .ok_or(AuthorityError::BindingMismatch)?;
        if record
            .rc2
            .as_ref()
            .is_none_or(|stored| stored.sha256 != authorization.sha256())
            || record
                .rc2_effect_authorization
                .as_ref()
                .is_none_or(|binding| {
                    !super::store_rc2_effect_lease::lease_matches(binding, &lease, id)
                })
        {
            return Err(AuthorityError::BindingMismatch);
        }
        let trust = record.rc2_evidence_trust.snapshot()?;
        if self
            .rc2_effect_ledger
            .cached(&cache.0, &cache.3, &retained, true)
            .is_ok_and(|same| same)
        {
            return replay_signing_effect_claim(
                evidence,
                authorization,
                &trust,
                &self.rc2_effect_ledger,
                lease,
            );
        }
        let effect = verify_signing_effect_claim_with_lease(
            evidence,
            authorization,
            &trust,
            &mut self.rc2_effect_ledger,
            lease,
        )?;
        self.rc2_effect_ledger
            .cache_effect(&cache.0, cache.1, cache.2, &cache.3, retained)
            .map_err(|_| AuthorityError::BindingMismatch)?;
        Ok(effect)
    }

    pub fn verify_rc2_native_evidence_closing_lease(
        &mut self,
        id: &PromotionId,
        evidence: RawRc2Evidence,
        record: &InspectedCanonicalPayload,
        effect: FixtureInFlightSigningEffect,
    ) -> Result<FixtureVerifiedNativeEvidence, AuthorityError> {
        let retained = StoredRawEvidence {
            raw: evidence.raw.clone(),
            signature: evidence.signature,
        };
        let cache = (
            effect.lease.namespace().to_owned(),
            effect.lease.authorization(),
            effect.lease.generation(),
            effect.lease.slot().to_owned(),
        );
        let trust = self
            .entries
            .get(id)
            .ok_or(AuthorityError::BindingMismatch)?
            .rc2_evidence_trust
            .snapshot()?;
        if self
            .rc2_effect_ledger
            .cached(&cache.0, &cache.3, &retained, false)
            .is_ok_and(|same| same)
        {
            return replay_native_evidence(
                evidence,
                record,
                &effect,
                &trust,
                &self.rc2_effect_ledger,
            );
        }
        let native = verify_native_evidence_closing_lease(
            evidence,
            record,
            effect,
            &trust,
            &mut self.rc2_effect_ledger,
        )?;
        self.rc2_effect_ledger
            .cache_native(&cache.0, cache.1, cache.2, &cache.3, retained)
            .map_err(|_| AuthorityError::BindingMismatch)?;
        Ok(native)
    }

    pub fn verify_rc2_signing_review(
        &self,
        id: &PromotionId,
        evidence: RawRc2Evidence,
        authorization: &InspectedCanonicalPayload,
        inventory: &InspectedCanonicalPayload,
        native: &[FixtureVerifiedNativeEvidence; 3],
    ) -> Result<FixtureVerifiedSigningReview, AuthorityError> {
        let record = self
            .entries
            .get(id)
            .ok_or(AuthorityError::BindingMismatch)?;
        if record
            .rc2
            .as_ref()
            .is_none_or(|stored| stored.sha256 != authorization.sha256())
        {
            return Err(AuthorityError::BindingMismatch);
        }
        verify_signing_review(
            evidence,
            authorization,
            inventory,
            native,
            &record.rc2_evidence_trust.snapshot()?,
        )
    }

    pub fn verify_rc2_update_metadata_issuance(
        &self,
        id: &PromotionId,
        evidence: RawRc2Evidence,
        authorization: &InspectedCanonicalPayload,
        inventory: &InspectedCanonicalPayload,
        metadata: &InspectedCanonicalPayload,
    ) -> Result<FixtureVerifiedUpdateMetadataIssuance, AuthorityError> {
        let record = self
            .entries
            .get(id)
            .ok_or(AuthorityError::BindingMismatch)?;
        if record
            .rc2
            .as_ref()
            .is_none_or(|stored| stored.sha256 != authorization.sha256())
        {
            return Err(AuthorityError::BindingMismatch);
        }
        verify_update_metadata_issuance(
            evidence,
            authorization,
            inventory,
            metadata,
            &record.rc2_evidence_trust.snapshot()?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prevalidate_rc2_bundle_with_claims(
        &mut self,
        id: &PromotionId,
        payloads: &[InspectedCanonicalPayload],
        effects: [FixtureVerifiedSigningEffect; 3],
        evidence: [FixtureVerifiedNativeEvidence; 3],
        review: FixtureVerifiedSigningReview,
        issuance: FixtureVerifiedUpdateMetadataIssuance,
        authorization: &InspectedCanonicalPayload,
    ) -> Result<FixturePrevalidatedSignedBundle, AuthorityError> {
        let record = self
            .entries
            .get(id)
            .ok_or(AuthorityError::BindingMismatch)?;
        if record.state != Some(PromotionState::SigningAuthorized)
            || record
                .rc2
                .as_ref()
                .is_none_or(|stage| stage.sha256 != authorization.sha256())
        {
            return Err(AuthorityError::BindingMismatch);
        }
        let lease_authorization = record
            .rc2_effect_authorization
            .clone()
            .ok_or(AuthorityError::BindingMismatch)?;
        FixturePrevalidatedSignedBundle::prevalidate_with_completed_leases(
            record.authority_instance,
            payloads,
            effects,
            evidence,
            review,
            issuance,
            authorization,
            &self.rc2_effect_ledger,
            &lease_authorization,
        )
    }
}
