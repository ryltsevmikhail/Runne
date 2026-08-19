//! Semantic validation of canonical publication-effect command histories.

use std::collections::BTreeSet;

use crate::Digest;
use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
use crate::publication_effect_ledger::{
    FixturePublicationEffectLedger, PublicationClaimBinding, PublicationCommandRecord,
};
use crate::publication_effect_types::{
    PublicationEffectError, PublicationEffectScope, PublicationEffectState, ReconcileOutcome,
};

pub(super) fn validate(
    ledger: &FixturePublicationEffectLedger,
) -> Result<(), PublicationEffectError> {
    let mut ids = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    for (namespace, binding) in &ledger.bindings {
        if namespace != &binding.scope.idempotency_namespace || binding.commands.is_empty() {
            return Err(corrupt());
        }
        for record in &binding.commands {
            if record.command.scope().idempotency_namespace != *namespace
                || record.fingerprint != record.command.fingerprint()?
                || record.outcome.command_fingerprint != record.fingerprint
                || record.outcome.generation != record.command.scope().generation
                || !ids.insert(record.command.id())
                || !fingerprints.insert(record.fingerprint)
            {
                return Err(corrupt());
            }
        }
        validate_sequence(binding)?;
    }
    Ok(())
}

#[derive(Default)]
struct Trace {
    current: Option<PublicationEffectState>,
    scope: Option<PublicationEffectScope>,
    capability: Option<Digest>,
    settlement: Option<Digest>,
    reconciliations: u8,
}

impl Trace {
    fn apply(
        &mut self,
        record: &PublicationCommandRecord,
    ) -> Result<PublicationEffectState, PublicationEffectError> {
        Ok(match &record.command {
            PublicationEffectCommand::Claim { scope, context, .. }
                if self.current.is_none() && current_context(scope, *context) =>
            {
                self.scope = Some(scope.clone());
                self.capability = Some(command_capability(scope, record.fingerprint));
                PublicationEffectState::Claimed
            }
            PublicationEffectCommand::Dispatch {
                scope,
                context,
                capability,
                ..
            } if self.exact(PublicationEffectState::Claimed, scope, *capability)
                && current_context(scope, *context) =>
            {
                PublicationEffectState::InFlight
            }
            PublicationEffectCommand::MarkUncertain {
                scope, capability, ..
            } if self.exact(PublicationEffectState::InFlight, scope, *capability) => {
                PublicationEffectState::Uncertain
            }
            PublicationEffectCommand::SucceedSettlement {
                scope,
                capability,
                evidence,
                ..
            } if self.exact(PublicationEffectState::InFlight, scope, *capability) => {
                self.settlement = Some(*evidence);
                PublicationEffectState::Succeeded
            }
            PublicationEffectCommand::Reconcile {
                scope,
                capability,
                result,
                evidence,
                ..
            } if self.exact(PublicationEffectState::Uncertain, scope, *capability) => {
                self.reconcile(*result, *evidence)
            }
            PublicationEffectCommand::Reclaim {
                scope,
                context,
                capability,
                ..
            } if self.current == Some(PublicationEffectState::ReconciledAbsent)
                && self.capability == Some(*capability)
                && self
                    .scope
                    .as_ref()
                    .is_some_and(|old| frozen_next(old, scope))
                && current_context(scope, *context) =>
            {
                self.scope = Some(scope.clone());
                self.capability = Some(command_capability(scope, record.fingerprint));
                PublicationEffectState::Claimed
            }
            _ => return Err(corrupt()),
        })
    }

    fn exact(
        &self,
        state: PublicationEffectState,
        scope: &PublicationEffectScope,
        cap: Digest,
    ) -> bool {
        self.current == Some(state)
            && self.scope.as_ref() == Some(scope)
            && self.capability == Some(cap)
    }

    fn reconcile(&mut self, result: ReconcileOutcome, evidence: Digest) -> PublicationEffectState {
        if result == ReconcileOutcome::Succeeded {
            self.settlement = Some(evidence);
        } else if result == ReconcileOutcome::Inconclusive {
            self.reconciliations = 1;
        }
        crate::publication_effect_command::outcome_state(result)
    }
}

fn validate_sequence(binding: &PublicationClaimBinding) -> Result<(), PublicationEffectError> {
    let mut trace = Trace::default();
    for record in &binding.commands {
        let next = trace.apply(record)?;
        let evidence = match &record.command {
            PublicationEffectCommand::SucceedSettlement { evidence, .. }
            | PublicationEffectCommand::Reconcile { evidence, .. } => Some(*evidence),
            _ => None,
        };
        if record.outcome.state != next || record.outcome.evidence != evidence {
            return Err(corrupt());
        }
        trace.current = Some(next);
    }
    (trace.scope.as_ref() == Some(&binding.scope)
        && trace.current == Some(binding.state)
        && trace.settlement == binding.settlement
        && trace.reconciliations == binding.reconciliations)
        .then_some(())
        .ok_or_else(corrupt)
}

fn command_capability(scope: &PublicationEffectScope, fingerprint: Digest) -> Digest {
    crate::publication_effect_command::capability_digest(scope, fingerprint)
}

fn frozen_next(old: &PublicationEffectScope, new: &PublicationEffectScope) -> bool {
    let mut expected = old.clone();
    let Some(next) = expected.generation.checked_add(1) else {
        return false;
    };
    expected.generation = next;
    expected == *new
}

const fn current_context(scope: &PublicationEffectScope, value: PublicationEffectContext) -> bool {
    value.observed_at >= scope.valid_from
        && value.observed_at < scope.expires_at
        && value.revocation_epoch == scope.revocation_epoch
        && value.allowlist_generation == scope.allowlist_generation
}

const fn corrupt() -> PublicationEffectError {
    PublicationEffectError::DurableStateUnavailable
}
