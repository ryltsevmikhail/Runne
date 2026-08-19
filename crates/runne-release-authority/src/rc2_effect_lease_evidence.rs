//! Raw-evidence replay cache bound to one persisted RC2 effect ledger.

use super::ledger::{FixtureRc2EffectLeaseLedger, StoredRawEvidence};
use super::types::{EffectLeaseError, FixtureRc2SigningDispatchLease, Rc2SigningEffectLeaseState};
use crate::Digest;

impl FixtureRc2EffectLeaseLedger {
    pub(crate) fn cache_effect(
        &mut self,
        namespace: &str,
        authorization: Digest,
        generation: u64,
        slot: &str,
        evidence: StoredRawEvidence,
    ) -> Result<bool, EffectLeaseError> {
        self.cache(namespace, authorization, generation, slot, evidence, true)
    }
    pub(crate) fn cache_native(
        &mut self,
        namespace: &str,
        authorization: Digest,
        generation: u64,
        slot: &str,
        evidence: StoredRawEvidence,
    ) -> Result<bool, EffectLeaseError> {
        self.cache(namespace, authorization, generation, slot, evidence, false)
    }
    fn cache(
        &mut self,
        namespace: &str,
        authorization: Digest,
        generation: u64,
        slot: &str,
        evidence: StoredRawEvidence,
        effect: bool,
    ) -> Result<bool, EffectLeaseError> {
        let binding = self
            .bindings
            .get(namespace)
            .ok_or(EffectLeaseError::InvalidLeaseState)?;
        if binding.authorization != authorization || binding.generation != generation {
            return Err(EffectLeaseError::StaleGeneration);
        }
        let target = if effect {
            &mut self.effect_evidence
        } else {
            &mut self.native_evidence
        };
        match target.get(&(namespace.into(), slot.into())) {
            Some(existing) if existing == &evidence => Ok(true),
            Some(_) => Err(EffectLeaseError::DivergentClaim),
            None => {
                target.insert((namespace.into(), slot.into()), evidence);
                Ok(false)
            }
        }
    }
    pub(crate) fn cached(
        &self,
        namespace: &str,
        slot: &str,
        evidence: &StoredRawEvidence,
        effect: bool,
    ) -> Result<bool, EffectLeaseError> {
        let source = if effect {
            &self.effect_evidence
        } else {
            &self.native_evidence
        };
        source
            .get(&(namespace.into(), slot.into()))
            .map(|stored| stored == evidence)
            .ok_or(EffectLeaseError::InvalidLeaseState)
    }
    pub(crate) fn has_state(
        &self,
        lease: &FixtureRc2SigningDispatchLease,
        state: Rc2SigningEffectLeaseState,
    ) -> Result<(), EffectLeaseError> {
        let index = self.slot_index(lease)?;
        (self.states[&lease.0.namespace][index] == state)
            .then_some(())
            .ok_or(EffectLeaseError::InvalidLeaseState)
    }
    pub(crate) fn has_replay_state(
        &self,
        lease: &FixtureRc2SigningDispatchLease,
    ) -> Result<(), EffectLeaseError> {
        let index = self.slot_index(lease)?;
        matches!(
            self.states[&lease.0.namespace][index],
            Rc2SigningEffectLeaseState::InFlight | Rc2SigningEffectLeaseState::Completed
        )
        .then_some(())
        .ok_or(EffectLeaseError::InvalidLeaseState)
    }
    fn slot_index(
        &self,
        lease: &FixtureRc2SigningDispatchLease,
    ) -> Result<usize, EffectLeaseError> {
        self.binding(&lease.0)?
            .slots
            .iter()
            .position(|slot| slot.0 == lease.0.slot)
            .ok_or(EffectLeaseError::StaleGeneration)
    }
}
