//! Durable fixture RC2 evidence-trust updates.

use crate::{
    AuthorityError, DurableFixturePromotionAuthority, FixtureEvidenceTrustState, PromotionId,
};

impl DurableFixturePromotionAuthority {
    /// Persist a fixture stage-trust snapshot under the durable authority lock.
    ///
    /// # Errors
    /// Returns an error when the promotion is absent or durable storage is unavailable.
    pub fn set_stage_trust(
        &mut self,
        id: &PromotionId,
        trust: crate::StageTrustFixture,
    ) -> Result<(), AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load()?;
        store
            .entries
            .get_mut(id)
            .ok_or(AuthorityError::InvalidTransition)?
            .stage_trust = crate::store_stage_trust::StoredStageTrust {
            now: trust.now,
            utc: trust.utc,
            root_epoch: trust.root_epoch,
            role_floor: trust.role_floor,
        };
        self.save(&store)
    }

    /// Persist the complete fixture verification trust root under the durable authority lock.
    ///
    /// # Errors
    /// Returns an error when the promotion is absent or durable persistence fails.
    pub fn set_rc2_evidence_trust_snapshot(
        &mut self,
        id: &PromotionId,
        trust: &FixtureEvidenceTrustState,
    ) -> Result<(), AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load()?;
        store.set_rc2_evidence_trust_snapshot(id, trust)?;
        self.save(&store)
    }
}
