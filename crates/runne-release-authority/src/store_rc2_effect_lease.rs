//! Promotion-store admission for fixture-only RC2 pre-sign leases.
#![allow(clippy::missing_errors_doc)] // Fixture promotion-store boundary.

use crate::signing_effect_evidence::verify_signing_backend_readback;
use crate::{
    AuthorityError, EffectLeaseError, FixtureRc2SigningDispatchLease,
    FixtureRc2SigningDispatchLeases, InMemoryPromotionStore, PromotionId, PromotionState,
};

impl InMemoryPromotionStore {
    /// Atomically reserve all three RC2 signing claims from persisted `SigningAuthorized` facts.
    pub fn reserve_rc2_signing_effects(
        &mut self,
        id: &PromotionId,
        expected_revision: u64,
    ) -> Result<FixtureRc2SigningDispatchLeases, EffectLeaseError> {
        let record = self
            .entries
            .get(id)
            .ok_or(EffectLeaseError::InvalidLeaseState)?;
        if record.authority_instance != self.authority_instance
            || record.state != Some(PromotionState::SigningAuthorized)
            || record.revision != expected_revision
        {
            return Err(EffectLeaseError::InvalidLeaseState);
        }
        let authorization = record
            .rc2_effect_authorization
            .as_ref()
            .ok_or(EffectLeaseError::InvalidLeaseState)?;
        let (now, epoch) = record
            .rc2_evidence_trust
            .snapshot()
            .map_err(|_| EffectLeaseError::InvalidLeaseState)?
            .timing();
        self.rc2_effect_ledger.reserve(authorization, now, epoch)
    }

    pub fn recover_rc2_signing_effects(
        &self,
        id: &PromotionId,
    ) -> Result<FixtureRc2SigningDispatchLeases, EffectLeaseError> {
        self.rc2_effect_ledger.recover(
            self.entries
                .get(id)
                .ok_or(EffectLeaseError::InvalidLeaseState)?
                .rc2_effect_authorization
                .as_ref()
                .ok_or(EffectLeaseError::InvalidLeaseState)?,
        )
    }

    pub fn dispatch_rc2_signing_effects(
        &mut self,
        id: &PromotionId,
        lease: FixtureRc2SigningDispatchLease,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        self.entries
            .get(id)
            .filter(|record| record.authority_instance == self.authority_instance)
            .ok_or(EffectLeaseError::InvalidLeaseState)?
            .rc2_effect_authorization
            .as_ref()
            .filter(|authorization| lease_matches(authorization, &lease, id))
            .ok_or(EffectLeaseError::InvalidLeaseState)?;
        let (now, epoch) = self
            .entries
            .get(id)
            .ok_or(EffectLeaseError::InvalidLeaseState)?
            .rc2_evidence_trust
            .snapshot()
            .map_err(|_| EffectLeaseError::InvalidLeaseState)?
            .timing();
        self.rc2_effect_ledger.dispatch(lease, now, epoch)
    }

    pub fn uncertain_rc2_signing_effects(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        self.rc2_effect_ledger.uncertain(lease)
    }

    pub fn reconcile_rc2_signing_effects(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
        readback: crate::Rc2SigningBackendReadbackFixture,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        self.rc2_effect_ledger.reconcile(lease, readback)
    }

    /// Verify and apply one raw backend readback without exposing the effect ledger.
    pub fn reconcile_rc2_signing_readback(
        &mut self,
        id: &PromotionId,
        lease: FixtureRc2SigningDispatchLease,
        evidence: crate::RawRc2Evidence,
    ) -> Result<FixtureRc2SigningDispatchLease, AuthorityError> {
        self.entries
            .get(id)
            .filter(|record| record.authority_instance == self.authority_instance)
            .ok_or(AuthorityError::BindingMismatch)?
            .rc2_effect_authorization
            .as_ref()
            .filter(|authorization| lease_matches(authorization, &lease, id))
            .ok_or(AuthorityError::BindingMismatch)?;
        let trust = self
            .entries
            .get(id)
            .ok_or(AuthorityError::BindingMismatch)?
            .rc2_evidence_trust
            .snapshot()?;
        let readback = verify_signing_backend_readback(evidence, &trust, &lease)?;
        self.reconcile_rc2_signing_effects(lease, readback)
            .map_err(|_| AuthorityError::BindingMismatch)
    }

    #[must_use]
    pub fn rc2_effect_claims(&self) -> Vec<crate::Rc2SigningEffectClaim> {
        self.rc2_effect_ledger.claims()
    }

    /// Production remains unprovisioned: fixture claim persistence is not a signing backend.
    pub const fn production_rc2_effect_status(&self) -> Result<(), AuthorityError> {
        Err(AuthorityError::AuthorityNotProvisioned)
    }
}

pub fn lease_matches(
    authorization: &crate::FixtureRc2SigningAuthorization,
    lease: &FixtureRc2SigningDispatchLease,
    id: &PromotionId,
) -> bool {
    let binding = authorization.fixture();
    binding.authority_instance == lease.authority_instance()
        && binding.promotion == id.0
        && binding.authorization == lease.authorization()
        && binding.generation == lease.generation()
}
