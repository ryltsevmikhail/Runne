//! Immutable scope and capability checks that precede publication-effect transitions.
#![allow(clippy::missing_errors_doc, dead_code)]

use crate::Digest;
use crate::publication_effect_ledger::{FixturePublicationEffectLedger, live_capability};
use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationEffectError, PublicationEffectScope,
};

impl FixturePublicationEffectLedger {
    pub(super) fn require_exact_live(
        &self,
        scope: &PublicationEffectScope,
        expected: Digest,
        actual: &FixturePublicationDispatch,
    ) -> Result<(), PublicationEffectError> {
        let binding = self
            .bindings
            .get(actual.namespace())
            .ok_or(PublicationEffectError::InvalidState)?;
        if binding.scope != *scope || actual.namespace() != scope.idempotency_namespace {
            return Err(PublicationEffectError::DivergentClaim);
        }
        exact_capability_generation(expected, actual, scope.generation)?;
        (live_capability(binding) == actual.capability())
            .then_some(())
            .ok_or(PublicationEffectError::StaleGeneration)
    }

    pub(super) fn require_exact_reclaim(
        &self,
        scope: &PublicationEffectScope,
        expected: Digest,
        actual: &FixturePublicationDispatch,
    ) -> Result<(), PublicationEffectError> {
        let binding = self
            .bindings
            .get(actual.namespace())
            .ok_or(PublicationEffectError::InvalidState)?;
        let mut next = binding.scope.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(PublicationEffectError::StaleGeneration)?;
        if next != *scope || actual.namespace() != scope.idempotency_namespace {
            return Err(PublicationEffectError::DivergentClaim);
        }
        exact_capability_generation(expected, actual, binding.scope.generation)?;
        (live_capability(binding) == actual.capability())
            .then_some(())
            .ok_or(PublicationEffectError::StaleGeneration)
    }
}

fn exact_capability_generation(
    expected: Digest,
    actual: &FixturePublicationDispatch,
    generation: u64,
) -> Result<(), PublicationEffectError> {
    (actual.capability() == expected && actual.generation() == generation)
        .then_some(())
        .ok_or(PublicationEffectError::StaleGeneration)
}
