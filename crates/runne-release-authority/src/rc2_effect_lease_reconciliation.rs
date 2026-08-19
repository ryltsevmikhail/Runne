#![allow(clippy::needless_pass_by_value)] // Readback fixture is consumed at the reconciliation boundary.

use super::{
    EffectLeaseError, FixtureRc2EffectLeaseLedger, FixtureRc2SigningDispatchLease,
    Rc2SigningBackendReadbackFixture, Rc2SigningEffectLeaseState,
};

const MAX_INCONCLUSIVE_READBACKS: u8 = 3;

impl FixtureRc2EffectLeaseLedger {
    pub fn reconcile(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
        readback: Rc2SigningBackendReadbackFixture,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        let binding = self.binding(&lease.0)?;
        let index = binding
            .slots
            .iter()
            .position(|slot| slot.0 == lease.0.slot)
            .ok_or(EffectLeaseError::StaleGeneration)?;
        if readback.slot != lease.0.slot
            || readback.artifact != binding.slots[index].1.to_hex()
            || readback.runner != binding.runner
        {
            return Err(EffectLeaseError::ReadbackMismatch);
        }
        let namespace = lease.0.namespace.clone();
        if self
            .states
            .get(&namespace)
            .ok_or(EffectLeaseError::InvalidLeaseState)?[index]
            != Rc2SigningEffectLeaseState::Uncertain
        {
            return Err(EffectLeaseError::InvalidLeaseState);
        }
        let state = self.readback_state(&namespace, index, readback.outcome)?;
        self.states
            .get_mut(&namespace)
            .ok_or(EffectLeaseError::InvalidLeaseState)?[index] = state;
        Ok(lease)
    }

    fn readback_state(
        &mut self,
        namespace: &str,
        index: usize,
        outcome: Rc2SigningEffectLeaseState,
    ) -> Result<Rc2SigningEffectLeaseState, EffectLeaseError> {
        if outcome != Rc2SigningEffectLeaseState::Uncertain {
            return Ok(outcome);
        }
        let attempts = self
            .reconciliations
            .get_mut(namespace)
            .ok_or(EffectLeaseError::InvalidLeaseState)?;
        attempts[index] = attempts[index].saturating_add(1);
        Ok(if attempts[index] >= MAX_INCONCLUSIVE_READBACKS {
            Rc2SigningEffectLeaseState::Blocked
        } else {
            Rc2SigningEffectLeaseState::Uncertain
        })
    }
}
