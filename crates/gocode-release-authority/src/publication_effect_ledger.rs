//! Candidate-global durable publication-effect namespace ledger (fixture reference).

#![allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    dead_code,
    clippy::redundant_pub_crate
)]

use std::collections::BTreeMap;

use crate::Digest;
use crate::publication_effect_command::PublicationEffectCommand;
use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationDispatchLease, PublicationEffectError,
    PublicationEffectRecovery, PublicationEffectReplay, PublicationEffectScope,
    PublicationEffectState, ReconcileOutcome,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PublicationCommandRecord {
    pub(super) command: PublicationEffectCommand,
    pub(super) fingerprint: Digest,
    pub(super) outcome: PublicationEffectReplay,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct PublicationClaimBinding {
    pub(super) scope: PublicationEffectScope,
    pub(super) state: PublicationEffectState,
    pub(super) reconciliations: u8,
    pub(super) settlement: Option<Digest>,
    pub(super) commands: Vec<PublicationCommandRecord>,
}

/// Candidate-global namespace ledger. It cannot dispatch to any external executor.
#[derive(Clone, Default)]
pub(crate) struct FixturePublicationEffectLedger {
    pub(super) bindings: BTreeMap<String, PublicationClaimBinding>,
}

impl FixturePublicationEffectLedger {
    pub(crate) fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Atomically claim one exact scope and mint a move-only dispatch capability.
    pub(crate) fn claim(
        &mut self,
        scope: &PublicationEffectScope,
        now: u64,
        revocation_epoch: u64,
        allowlist_generation: u64,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        if !scope.is_well_formed() {
            return Err(PublicationEffectError::InvalidAuthorization);
        }
        current(scope, now, revocation_epoch, allowlist_generation)?;
        if let Some(existing) = self.bindings.get(&scope.idempotency_namespace) {
            if existing.scope.promotion != scope.promotion {
                return Err(PublicationEffectError::NamespaceAlreadyClaimed);
            }
            return if existing.scope == *scope {
                Err(PublicationEffectError::DuplicateClaim)
            } else {
                Err(PublicationEffectError::DivergentClaim)
            };
        }
        self.bindings.insert(
            scope.idempotency_namespace.clone(),
            PublicationClaimBinding {
                scope: scope.clone(),
                state: PublicationEffectState::Claimed,
                reconciliations: 0,
                settlement: None,
                commands: Vec::new(),
            },
        );
        Ok(lease(scope))
    }

    pub(crate) fn recover(
        &self,
        scope: &PublicationEffectScope,
    ) -> Result<PublicationEffectRecovery, PublicationEffectError> {
        self.bindings
            .get(&scope.idempotency_namespace)
            .filter(|binding| binding.scope == *scope)
            .map(|binding| PublicationEffectRecovery {
                state: binding.state,
                generation: binding.scope.generation,
                settlement: binding.settlement,
            })
            .ok_or(PublicationEffectError::DivergentClaim)
    }

    /// Transition `Claimed -> InFlight`, consuming the move-only capability.
    pub(crate) fn dispatch(
        &mut self,
        capability: FixturePublicationDispatch,
        now: u64,
        revocation_epoch: u64,
        allowlist_generation: u64,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        self.checked(capability, PublicationEffectState::Claimed, |binding| {
            current(&binding.scope, now, revocation_epoch, allowlist_generation)?;
            binding.state = PublicationEffectState::InFlight;
            Ok(())
        })
    }

    /// Transition `InFlight -> Succeeded`, retaining the exact signed settlement digest.
    pub(crate) fn succeed(
        &mut self,
        capability: FixturePublicationDispatch,
        settlement_digest: Digest,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        self.checked(capability, PublicationEffectState::InFlight, |binding| {
            binding.settlement = Some(settlement_digest);
            binding.state = PublicationEffectState::Succeeded;
            Ok(())
        })
    }

    /// Transition `InFlight -> Uncertain` after an inconclusive external response.
    pub(crate) fn mark_uncertain(
        &mut self,
        capability: FixturePublicationDispatch,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        self.checked(capability, PublicationEffectState::InFlight, |binding| {
            binding.state = PublicationEffectState::Uncertain;
            Ok(())
        })
    }

    /// Reconcile `Uncertain` with a signed readback; bounded and terminal.
    ///
    /// `Inconclusive` increments the reconciliation counter and becomes terminal
    /// `Blocked` only after the bound is reached; `Succeeded`/`Absent` settle.
    pub(crate) fn reconcile(
        &mut self,
        capability: FixturePublicationDispatch,
        outcome: ReconcileOutcome,
        readback_digest: Digest,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        self.checked(capability, PublicationEffectState::Uncertain, |binding| {
            let target = match outcome {
                ReconcileOutcome::Succeeded => {
                    binding.settlement = Some(readback_digest);
                    PublicationEffectState::ReconciledSucceeded
                }
                ReconcileOutcome::Absent => PublicationEffectState::ReconciledAbsent,
                ReconcileOutcome::Inconclusive => {
                    binding.reconciliations += 1;
                    if binding.reconciliations >= MAX_RECONCILIATIONS {
                        PublicationEffectState::Blocked
                    } else {
                        PublicationEffectState::Uncertain
                    }
                }
            };
            binding.state = target;
            Ok(())
        })
    }

    /// Re-open a claim at exactly generation + 1 after authenticated absence.
    pub(crate) fn reclaim(
        &mut self,
        capability: FixturePublicationDispatch,
        scope: &PublicationEffectScope,
        now: u64,
        revocation_epoch: u64,
        allowlist_generation: u64,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        self.checked(
            capability,
            PublicationEffectState::ReconciledAbsent,
            |binding| {
                let next = binding
                    .scope
                    .generation
                    .checked_add(1)
                    .ok_or(PublicationEffectError::StaleGeneration)?;
                let mut frozen = binding.scope.clone();
                frozen.generation = next;
                if *scope != frozen {
                    return Err(PublicationEffectError::DivergentClaim);
                }
                current(scope, now, revocation_epoch, allowlist_generation)?;
                binding.scope = scope.clone();
                binding.state = PublicationEffectState::Claimed;
                binding.reconciliations = 0;
                Ok(())
            },
        )
    }

    #[must_use]
    pub(crate) fn state(&self, namespace: &str) -> Option<PublicationEffectState> {
        self.bindings.get(namespace).map(|binding| binding.state)
    }

    #[must_use]
    pub(crate) fn settlement(&self, namespace: &str) -> Option<Digest> {
        self.bindings
            .get(namespace)
            .and_then(|binding| binding.settlement)
    }

    fn checked(
        &mut self,
        capability: FixturePublicationDispatch,
        from: PublicationEffectState,
        apply: impl FnOnce(&mut PublicationClaimBinding) -> Result<(), PublicationEffectError>,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        let binding = self
            .bindings
            .get_mut(capability.namespace())
            .ok_or(PublicationEffectError::InvalidState)?;
        if binding.scope.authority_instance != capability.authority_instance()
            || binding.scope.generation != capability.generation()
            || live_capability(binding) != capability.capability()
        {
            return Err(PublicationEffectError::StaleGeneration);
        }
        if binding.state != from {
            return Err(PublicationEffectError::InvalidState);
        }
        apply(binding)?;
        let scope = binding.scope.clone();
        Ok(lease(&scope))
    }
}

impl FixturePublicationEffectLedger {
    pub(crate) fn merge_from(&mut self, other: &Self) -> Result<(), PublicationEffectError> {
        for (namespace, binding) in &other.bindings {
            if let Some(existing) = self.bindings.get(namespace) {
                if existing == binding {
                    continue;
                }
                return Err(if existing.scope.promotion == binding.scope.promotion {
                    PublicationEffectError::DivergentClaim
                } else {
                    PublicationEffectError::NamespaceAlreadyClaimed
                });
            }
            self.bindings.insert(namespace.clone(), binding.clone());
        }
        Ok(())
    }
}

const MAX_RECONCILIATIONS: u8 = 1;

fn lease(scope: &PublicationEffectScope) -> FixturePublicationDispatch {
    FixturePublicationDispatch(PublicationDispatchLease {
        authority_instance: scope.authority_instance,
        idempotency_namespace: scope.idempotency_namespace.clone(),
        generation: scope.generation,
        capability: Digest::fixture([0; 32]),
    })
}

pub(super) fn live_capability(binding: &PublicationClaimBinding) -> Digest {
    binding
        .commands
        .iter()
        .rev()
        .find(|record| {
            matches!(
                record.command,
                PublicationEffectCommand::Claim { .. } | PublicationEffectCommand::Reclaim { .. }
            )
        })
        .map_or_else(
            || Digest::fixture([0; 32]),
            |record| {
                crate::publication_effect_command::capability_digest(
                    record.command.scope(),
                    record.fingerprint,
                )
            },
        )
}

fn current(
    scope: &PublicationEffectScope,
    now: u64,
    revocation_epoch: u64,
    allowlist_generation: u64,
) -> Result<(), PublicationEffectError> {
    (now >= scope.valid_from
        && now < scope.expires_at
        && revocation_epoch == scope.revocation_epoch
        && allowlist_generation == scope.allowlist_generation)
        .then_some(())
        .ok_or(PublicationEffectError::AuthorizationExpiredOrRevoked)
}
