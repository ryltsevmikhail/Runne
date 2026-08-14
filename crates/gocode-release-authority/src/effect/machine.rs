use std::collections::BTreeMap;

use super::{
    EffectError, EffectSnapshot, EffectState, EffectTransition, InertEffectTransitionValidator,
    PublicationAuthorizedBinding, PublicationEffectRequest, PublicationEffectTransitionValidator,
};
use crate::Digest;

const MAX_RECONCILIATIONS: u8 = 3;

#[derive(Clone)]
struct EffectRecord {
    request: PublicationEffectRequest,
    snapshot: EffectSnapshot,
    authorization: Option<Digest>,
    reconciliations: u8,
}

/// Fixture-only in-memory model. It has no executor or external-effect capability.
#[derive(Default)]
pub struct FixturePublicationEffectMachine {
    records: BTreeMap<String, EffectRecord>,
}

impl FixturePublicationEffectMachine {
    /// # Errors
    ///
    /// Returns an error when an idempotency namespace is already bound.
    pub fn plan(
        &mut self,
        request: PublicationEffectRequest,
    ) -> Result<EffectSnapshot, EffectError> {
        let namespace = request.namespace().to_owned();
        if let Some(existing) = self.records.get(&namespace) {
            return if existing.request == request {
                Err(EffectError::DuplicateIdempotencyNamespace)
            } else {
                Err(EffectError::DivergentIdempotencyNamespace)
            };
        }
        let snapshot = EffectSnapshot {
            state: EffectState::Planned,
            generation: 0,
        };
        self.records.insert(
            namespace,
            EffectRecord {
                request,
                snapshot,
                authorization: None,
                reconciliations: 0,
            },
        );
        Ok(snapshot)
    }

    /// # Errors
    ///
    /// Returns an error for absent, expired, revoked, replayed, or stale authorization.
    pub fn claim(
        &mut self,
        request: &PublicationEffectRequest,
        binding: Option<&PublicationAuthorizedBinding>,
        generation: u64,
        now: u64,
        current_revocation_epoch: u64,
    ) -> Result<EffectSnapshot, EffectError> {
        let record = self.record_mut(request)?;
        let binding = binding.ok_or(EffectError::MissingPublicationAuthorization)?;
        if !binding.matches(request)
            || record
                .authorization
                .is_some_and(|authorization| authorization != binding.authorization())
        {
            return Err(EffectError::AuthorizationBindingMismatch);
        }
        if now < request.valid_from()
            || now >= request.expires_at()
            || current_revocation_epoch != request.revocation_epoch()
        {
            return Err(EffectError::AuthorizationExpiredOrRevoked);
        }
        let prior = record.snapshot;
        match prior.state {
            EffectState::Planned => Self::same_generation(prior, generation)?,
            EffectState::ReconciledAbsent => Self::retry_generation(prior, generation)?,
            _ => return Err(EffectError::InvalidTransition),
        }
        let next = EffectSnapshot {
            state: EffectState::Claimed,
            generation,
        };
        InertEffectTransitionValidator.validate(EffectTransition {
            from: prior,
            to: next,
        })?;
        record.snapshot = next;
        record.authorization = Some(binding.authorization());
        Ok(next)
    }

    /// # Errors
    ///
    /// Returns an error unless a current claimed generation starts the bounded effect attempt.
    pub fn start(
        &mut self,
        request: &PublicationEffectRequest,
        generation: u64,
        now: u64,
        current_revocation_epoch: u64,
    ) -> Result<EffectSnapshot, EffectError> {
        if now < request.valid_from()
            || now >= request.expires_at()
            || current_revocation_epoch != request.revocation_epoch()
        {
            return Err(EffectError::AuthorizationExpiredOrRevoked);
        }
        self.transition(request, generation, EffectState::InFlight)
    }

    /// # Errors
    ///
    /// Returns an error unless the current in-flight attempt has a known result.
    pub fn succeed(
        &mut self,
        request: &PublicationEffectRequest,
        generation: u64,
    ) -> Result<EffectSnapshot, EffectError> {
        self.transition(request, generation, EffectState::Succeeded)
    }

    /// # Errors
    ///
    /// Returns an error unless the current in-flight attempt has an uncertain result.
    pub fn uncertain(
        &mut self,
        request: &PublicationEffectRequest,
        generation: u64,
    ) -> Result<EffectSnapshot, EffectError> {
        self.transition(request, generation, EffectState::Uncertain)
    }

    /// # Errors
    ///
    /// Returns an error unless bounded reconciliation proves the destination is absent.
    pub fn reconcile_absent(
        &mut self,
        request: &PublicationEffectRequest,
        generation: u64,
    ) -> Result<EffectSnapshot, EffectError> {
        self.reconcile(request, generation, EffectState::ReconciledAbsent)
    }

    /// # Errors
    ///
    /// Returns an error unless bounded reconciliation proves the destination succeeded.
    pub fn reconcile_succeeded(
        &mut self,
        request: &PublicationEffectRequest,
        generation: u64,
    ) -> Result<EffectSnapshot, EffectError> {
        self.reconcile(request, generation, EffectState::ReconciledSucceeded)
    }

    /// # Errors
    ///
    /// Returns an error unless bounded reconciliation blocks the uncertain effect.
    pub fn block(
        &mut self,
        request: &PublicationEffectRequest,
        generation: u64,
    ) -> Result<EffectSnapshot, EffectError> {
        self.reconcile(request, generation, EffectState::Blocked)
    }

    fn reconcile(
        &mut self,
        request: &PublicationEffectRequest,
        generation: u64,
        to: EffectState,
    ) -> Result<EffectSnapshot, EffectError> {
        let record = self.record_mut(request)?;
        if record.reconciliations >= MAX_RECONCILIATIONS {
            return Err(EffectError::ReconciliationBoundExceeded);
        }
        let snapshot = Self::apply(record, generation, to)?;
        record.reconciliations += 1;
        Ok(snapshot)
    }

    fn transition(
        &mut self,
        request: &PublicationEffectRequest,
        generation: u64,
        to: EffectState,
    ) -> Result<EffectSnapshot, EffectError> {
        Self::apply(self.record_mut(request)?, generation, to)
    }

    fn apply(
        record: &mut EffectRecord,
        generation: u64,
        to: EffectState,
    ) -> Result<EffectSnapshot, EffectError> {
        Self::same_generation(record.snapshot, generation)?;
        let next = EffectSnapshot {
            state: to,
            generation,
        };
        InertEffectTransitionValidator.validate(EffectTransition {
            from: record.snapshot,
            to: next,
        })?;
        record.snapshot = next;
        Ok(next)
    }

    fn record_mut(
        &mut self,
        request: &PublicationEffectRequest,
    ) -> Result<&mut EffectRecord, EffectError> {
        let record = self
            .records
            .get_mut(request.namespace())
            .ok_or(EffectError::MissingPublicationAuthorization)?;
        if record.request == *request {
            Ok(record)
        } else {
            Err(EffectError::DivergentIdempotencyNamespace)
        }
    }

    const fn same_generation(snapshot: EffectSnapshot, generation: u64) -> Result<(), EffectError> {
        if snapshot.generation == generation {
            Ok(())
        } else {
            Err(EffectError::StaleGeneration)
        }
    }

    fn retry_generation(snapshot: EffectSnapshot, generation: u64) -> Result<(), EffectError> {
        if snapshot
            .generation
            .checked_add(1)
            .is_some_and(|expected| expected == generation)
        {
            Ok(())
        } else {
            Err(EffectError::StaleGeneration)
        }
    }
}
