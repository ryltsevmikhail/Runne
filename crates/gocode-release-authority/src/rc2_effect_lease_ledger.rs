#![allow(clippy::missing_errors_doc, clippy::needless_pass_by_value)] // Move-only leases/readback.
use std::collections::BTreeMap;

use super::types::{
    EffectLeaseError, FixtureRc2SigningAuthorization, FixtureRc2SigningDispatchLease,
    FixtureRc2SigningDispatchLeases, Rc2SigningAuthorizationFixture, Rc2SigningDispatchLease,
    Rc2SigningEffectClaim, Rc2SigningEffectLeaseState,
};
use crate::Digest;

#[derive(Clone)]
pub(super) struct ClaimBinding {
    pub(super) authority_instance: Digest,
    pub(super) promotion: String,
    pub(super) revision: u64,
    pub(super) authorization: Digest,
    pub(super) workflow: Digest,
    pub(super) signer: String,
    pub(super) runner: String,
    pub(super) slots: [(String, Digest, u64); 3],
    pub(super) generation: u64,
    pub(super) valid_from: u64,
    pub(super) expires_at: u64,
    pub(super) epoch: u64,
}

/// Fixture-only global namespace ledger. It cannot dispatch or contact a signing backend.
#[derive(Default)]
pub struct FixtureRc2EffectLeaseLedger {
    pub(super) bindings: BTreeMap<String, ClaimBinding>,
    pub(super) states: BTreeMap<String, [Rc2SigningEffectLeaseState; 3]>,
    pub(super) reconciliations: BTreeMap<String, [u8; 3]>,
    pub(super) consumed: BTreeMap<String, Digest>,
    pub(super) effect_evidence: BTreeMap<(String, String), StoredRawEvidence>,
    pub(super) native_evidence: BTreeMap<(String, String), StoredRawEvidence>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct StoredRawEvidence {
    pub(crate) raw: Vec<u8>,
    pub(crate) signature: [u8; 64],
}

impl Clone for FixtureRc2EffectLeaseLedger {
    fn clone(&self) -> Self {
        Self {
            bindings: self.bindings.clone(),
            states: self.states.clone(),
            reconciliations: self.reconciliations.clone(),
            consumed: self.consumed.clone(),
            effect_evidence: self.effect_evidence.clone(),
            native_evidence: self.native_evidence.clone(),
        }
    }
}

impl FixtureRc2EffectLeaseLedger {
    pub(crate) fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
    pub fn reserve(
        &mut self,
        authorization: &FixtureRc2SigningAuthorization,
        now: u64,
        epoch: u64,
    ) -> Result<FixtureRc2SigningDispatchLeases, EffectLeaseError> {
        let input = &authorization.0;
        current(input, now, epoch)?;
        let binding = ClaimBinding::from(input);
        if let Some(existing) = self.bindings.get(&input.namespace) {
            if existing.promotion != binding.promotion {
                return Err(EffectLeaseError::NamespaceAlreadyClaimed);
            }
            return if same(existing, &binding) {
                Err(EffectLeaseError::DuplicateClaim)
            } else {
                Err(EffectLeaseError::DivergentClaim)
            };
        }
        self.bindings.insert(input.namespace.clone(), binding);
        self.states.insert(
            input.namespace.clone(),
            [Rc2SigningEffectLeaseState::Claimed; 3],
        );
        self.reconciliations.insert(input.namespace.clone(), [0; 3]);
        Ok(leases(input))
    }

    /// Recover only an exact persisted reservation after a process restart.
    pub fn recover(
        &self,
        authorization: &FixtureRc2SigningAuthorization,
    ) -> Result<FixtureRc2SigningDispatchLeases, EffectLeaseError> {
        let input = &authorization.0;
        let binding = self
            .bindings
            .get(&input.namespace)
            .ok_or(EffectLeaseError::InvalidLeaseState)?;
        same(binding, &ClaimBinding::from(input))
            .then_some(leases(input))
            .ok_or(EffectLeaseError::DivergentClaim)
    }

    pub fn dispatch(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
        now: u64,
        epoch: u64,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        let binding = self.binding(&lease.0)?;
        if now < binding.valid_from || now >= binding.expires_at || epoch != binding.epoch {
            return Err(EffectLeaseError::AuthorizationExpiredOrRevoked);
        }
        self.settle(
            lease,
            Rc2SigningEffectLeaseState::Claimed,
            Rc2SigningEffectLeaseState::InFlight,
        )
    }

    pub fn uncertain(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        self.settle(
            lease,
            Rc2SigningEffectLeaseState::InFlight,
            Rc2SigningEffectLeaseState::Uncertain,
        )
    }

    pub fn complete(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        self.settle(
            lease,
            Rc2SigningEffectLeaseState::InFlight,
            Rc2SigningEffectLeaseState::Completed,
        )
    }

    #[must_use]
    pub fn claims(&self) -> Vec<Rc2SigningEffectClaim> {
        self.bindings
            .iter()
            .filter(|(namespace, _)| !self.consumed.contains_key(*namespace))
            .flat_map(|(namespace, binding)| {
                self.states[namespace]
                    .iter()
                    .enumerate()
                    .map(move |(index, state)| Rc2SigningEffectClaim {
                        slot: binding.slots[index].0.clone(),
                        state: *state,
                        generation: binding.generation,
                    })
            })
            .collect()
    }

    #[must_use]
    pub fn all_completed(&self, authorization: &FixtureRc2SigningAuthorization) -> bool {
        self.bindings
            .get(&authorization.0.namespace)
            .is_some_and(|binding| {
                same(binding, &ClaimBinding::from(&authorization.0))
                    && self.states[&authorization.0.namespace]
                        .iter()
                        .all(|state| *state == Rc2SigningEffectLeaseState::Completed)
            })
    }

    fn settle(
        &mut self,
        lease: FixtureRc2SigningDispatchLease,
        from: Rc2SigningEffectLeaseState,
        to: Rc2SigningEffectLeaseState,
    ) -> Result<FixtureRc2SigningDispatchLease, EffectLeaseError> {
        let namespace = lease.0.namespace.clone();
        let index = self
            .binding(&lease.0)?
            .slots
            .iter()
            .position(|slot| slot.0 == lease.0.slot)
            .ok_or(EffectLeaseError::StaleGeneration)?;
        let states = self
            .states
            .get_mut(&namespace)
            .ok_or(EffectLeaseError::InvalidLeaseState)?;
        if states[index] != from {
            return Err(EffectLeaseError::InvalidLeaseState);
        }
        states[index] = to;
        Ok(lease)
    }

    pub(super) fn binding(
        &self,
        lease: &Rc2SigningDispatchLease,
    ) -> Result<&ClaimBinding, EffectLeaseError> {
        let binding = self
            .bindings
            .get(&lease.namespace)
            .ok_or(EffectLeaseError::InvalidLeaseState)?;
        (binding.authority_instance == lease.authority_instance
            && binding.authorization == lease.authorization
            && binding.generation == lease.generation)
            .then_some(binding)
            .ok_or(EffectLeaseError::StaleGeneration)
    }
}

impl From<&Rc2SigningAuthorizationFixture> for ClaimBinding {
    fn from(input: &Rc2SigningAuthorizationFixture) -> Self {
        Self {
            authority_instance: input.authority_instance,
            promotion: input.promotion.clone(),
            revision: input.revision,
            authorization: input.authorization,
            workflow: input.workflow,
            signer: input.signer.clone(),
            runner: input.runner.clone(),
            slots: input.slots.clone(),
            generation: input.generation,
            valid_from: input.valid_from,
            expires_at: input.expires_at,
            epoch: input.revocation_epoch,
        }
    }
}

fn current(
    input: &Rc2SigningAuthorizationFixture,
    now: u64,
    epoch: u64,
) -> Result<(), EffectLeaseError> {
    (now >= input.valid_from && now < input.expires_at && epoch == input.revocation_epoch)
        .then_some(())
        .ok_or(EffectLeaseError::AuthorizationExpiredOrRevoked)
}

fn leases(input: &Rc2SigningAuthorizationFixture) -> FixtureRc2SigningDispatchLeases {
    FixtureRc2SigningDispatchLeases(
        input
            .slots
            .clone()
            .map(|(slot, _, _)| Some(lease(input, slot))),
    )
}
fn lease(input: &Rc2SigningAuthorizationFixture, slot: String) -> FixtureRc2SigningDispatchLease {
    FixtureRc2SigningDispatchLease(Rc2SigningDispatchLease {
        authority_instance: input.authority_instance,
        namespace: input.namespace.clone(),
        authorization: input.authorization,
        generation: input.generation,
        slot,
    })
}

fn same(left: &ClaimBinding, right: &ClaimBinding) -> bool {
    left.authority_instance == right.authority_instance
        && left.promotion == right.promotion
        && left.revision == right.revision
        && left.authorization == right.authorization
        && left.workflow == right.workflow
        && left.signer == right.signer
        && left.runner == right.runner
        && left.slots == right.slots
        && left.generation == right.generation
        && left.valid_from == right.valid_from
        && left.expires_at == right.expires_at
        && left.epoch == right.epoch
}
