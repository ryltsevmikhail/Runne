//! Durable fixture trust-snapshot update.

use crate::{AuthorityError, DurableFixturePromotionStore, PromotionId, StageTrustFixture};

impl DurableFixturePromotionStore {
    /// Persist the fixture's authenticated stage trust snapshot under the durable lock.
    ///
    /// # Errors
    /// Returns an error for a missing promotion or unavailable durable storage.
    pub fn set_stage_trust(
        &mut self,
        id: &PromotionId,
        trust: StageTrustFixture,
    ) -> Result<(), AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let (stored, mut record) = self.load()?;
        if stored != *id {
            return Err(AuthorityError::BindingMismatch);
        }
        record.stage_trust = crate::store_stage_trust::StoredStageTrust {
            now: trust.now,
            utc: trust.utc,
            root_epoch: trust.root_epoch,
            role_floor: trust.role_floor,
        };
        self.save(id, &record)
    }
}
