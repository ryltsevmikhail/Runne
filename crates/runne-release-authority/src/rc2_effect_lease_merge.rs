//! Collision-safe merge of fixture RC2 effect ledgers.

use super::ledger::{ClaimBinding, FixtureRc2EffectLeaseLedger};
use super::types::EffectLeaseError;

impl FixtureRc2EffectLeaseLedger {
    pub(crate) fn merge_from(&mut self, other: &Self) -> Result<(), EffectLeaseError> {
        for (namespace, binding) in &other.bindings {
            let states = other
                .states
                .get(namespace)
                .ok_or(EffectLeaseError::DurableStateUnavailable)?;
            let reconciliations = other
                .reconciliations
                .get(namespace)
                .ok_or(EffectLeaseError::DurableStateUnavailable)?;
            let consumed = other.consumed.get(namespace).copied();
            let effect_evidence = other
                .effect_evidence
                .iter()
                .filter(|((current, _), _)| current == namespace)
                .collect::<Vec<_>>();
            let native_evidence = other
                .native_evidence
                .iter()
                .filter(|((current, _), _)| current == namespace)
                .collect::<Vec<_>>();
            if let Some(existing) = self.bindings.get(namespace) {
                if same(existing, binding)
                    && self.states.get(namespace) == Some(states)
                    && self.reconciliations.get(namespace) == Some(reconciliations)
                    && self.consumed.get(namespace).copied() == consumed
                    && self
                        .effect_evidence
                        .iter()
                        .filter(|((current, _), _)| current == namespace)
                        .collect::<Vec<_>>()
                        == effect_evidence
                    && self
                        .native_evidence
                        .iter()
                        .filter(|((current, _), _)| current == namespace)
                        .collect::<Vec<_>>()
                        == native_evidence
                {
                    continue;
                }
                return Err(if existing.promotion == binding.promotion {
                    EffectLeaseError::DivergentClaim
                } else {
                    EffectLeaseError::NamespaceAlreadyClaimed
                });
            }
            self.bindings.insert(namespace.clone(), binding.clone());
            self.states.insert(namespace.clone(), *states);
            self.reconciliations
                .insert(namespace.clone(), *reconciliations);
            if let Some(commitment) = consumed {
                self.consumed.insert(namespace.clone(), commitment);
            }
            self.effect_evidence.extend(
                effect_evidence
                    .into_iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
            self.native_evidence.extend(
                native_evidence
                    .into_iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
        Ok(())
    }
}

fn same(left: &ClaimBinding, right: &ClaimBinding) -> bool {
    left.promotion == right.promotion
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
