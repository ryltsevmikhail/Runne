//! Durable RC2 signing-effect forwarding under the same authority transaction lock.
#![allow(clippy::missing_errors_doc)] // Fixture-only durable boundary.

use crate::{
    DurableFixturePromotionAuthority, EffectLeaseError, FixtureRc2SigningDispatchLease,
    FixtureRc2SigningDispatchLeases, PromotionId, Rc2SigningBackendReadbackFixture,
};

impl DurableFixturePromotionAuthority {
    pub fn reserve_rc2_signing_effects(
        &mut self,
        id: &PromotionId,
        revision: u64,
    ) -> Result<FixtureRc2SigningDispatchLeases, EffectLeaseError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self
            .load()
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        let leases = store.reserve_rc2_signing_effects(id, revision)?;
        self.save(&store)
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        Ok(leases)
    }
    pub fn recover_rc2_signing_effects(
        &self,
        id: &PromotionId,
    ) -> Result<FixtureRc2SigningDispatchLeases, EffectLeaseError> {
        let _guard = self.lock.borrow_mut();
        self.load()
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?
            .recover_rc2_signing_effects(id)
    }
    pub fn dispatch_rc2_signing_effects(
        &mut self,
        id: &PromotionId,
        lease: FixtureRc2SigningDispatchLease,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self
            .load()
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        let lease = store.dispatch_rc2_signing_effects(id, lease)?;
        self.save(&store)
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        Ok(lease)
    }
    pub fn uncertain_rc2_signing_effects(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self
            .load()
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        let lease = store.uncertain_rc2_signing_effects(lease)?;
        self.save(&store)
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        Ok(lease)
    }
    pub fn reconcile_rc2_signing_effects(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
        readback: Rc2SigningBackendReadbackFixture,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self
            .load()
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        let lease = store.reconcile_rc2_signing_effects(lease, readback)?;
        self.save(&store)
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        Ok(lease)
    }
    /// Verify raw registered-backend readback and atomically persist its reconciliation.
    pub fn reconcile_rc2_signing_readback(
        &mut self,
        id: &PromotionId,
        lease: FixtureRc2SigningDispatchLease,
        evidence: crate::RawRc2Evidence,
    ) -> Result<FixtureRc2SigningDispatchLease, crate::AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load()?;
        let lease = store.reconcile_rc2_signing_readback(id, lease, evidence)?;
        self.save(&store)?;
        Ok(lease)
    }

    /// Verify one raw signing claim and durably consume only its matching dispatch lease.
    pub fn verify_rc2_signing_effect_with_lease(
        &mut self,
        id: &PromotionId,
        evidence: crate::RawRc2Evidence,
        authorization: &crate::InspectedCanonicalPayload,
        lease: FixtureRc2SigningDispatchLease,
    ) -> Result<crate::FixtureInFlightSigningEffect, crate::AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load()?;
        let effect =
            store.verify_rc2_signing_effect_with_lease(id, evidence, authorization, lease)?;
        self.save(&store)?;
        Ok(effect)
    }

    /// Verify one raw native result and durably close its exact in-flight lease.
    pub fn verify_rc2_native_evidence_closing_lease(
        &mut self,
        id: &PromotionId,
        evidence: crate::RawRc2Evidence,
        record: &crate::InspectedCanonicalPayload,
        effect: crate::FixtureInFlightSigningEffect,
    ) -> Result<crate::FixtureVerifiedNativeEvidence, crate::AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load()?;
        let native =
            store.verify_rc2_native_evidence_closing_lease(id, evidence, record, effect)?;
        self.save(&store)?;
        Ok(native)
    }

    /// Verify raw review evidence under the same durable promotion authority lock.
    pub fn verify_rc2_signing_review(
        &self,
        id: &PromotionId,
        evidence: crate::RawRc2Evidence,
        authorization: &crate::InspectedCanonicalPayload,
        inventory: &crate::InspectedCanonicalPayload,
        native: &[crate::FixtureVerifiedNativeEvidence; 3],
    ) -> Result<crate::FixtureVerifiedSigningReview, crate::AuthorityError> {
        let _guard = self.lock.borrow_mut();
        self.load()?
            .verify_rc2_signing_review(id, evidence, authorization, inventory, native)
    }

    /// Verify raw metadata issuance under the same durable promotion authority lock.
    pub fn verify_rc2_update_metadata_issuance(
        &self,
        id: &PromotionId,
        evidence: crate::RawRc2Evidence,
        authorization: &crate::InspectedCanonicalPayload,
        inventory: &crate::InspectedCanonicalPayload,
        metadata: &crate::InspectedCanonicalPayload,
    ) -> Result<crate::FixtureVerifiedUpdateMetadataIssuance, crate::AuthorityError> {
        let _guard = self.lock.borrow_mut();
        self.load()?.verify_rc2_update_metadata_issuance(
            id,
            evidence,
            authorization,
            inventory,
            metadata,
        )
    }

    #[allow(clippy::too_many_arguments)]
    /// Close all three leased claims and prevalidate their one exact final RC2 bundle durably.
    pub fn prevalidate_rc2_bundle_with_claims(
        &mut self,
        id: &PromotionId,
        payloads: &[crate::InspectedCanonicalPayload],
        effects: [crate::FixtureVerifiedSigningEffect; 3],
        evidence: [crate::FixtureVerifiedNativeEvidence; 3],
        review: crate::FixtureVerifiedSigningReview,
        issuance: crate::FixtureVerifiedUpdateMetadataIssuance,
        authorization: &crate::InspectedCanonicalPayload,
    ) -> Result<crate::FixturePrevalidatedSignedBundle, crate::AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load()?;
        let bundle = store.prevalidate_rc2_bundle_with_claims(
            id,
            payloads,
            effects,
            evidence,
            review,
            issuance,
            authorization,
        )?;
        self.save(&store)?;
        Ok(bundle)
    }
}
