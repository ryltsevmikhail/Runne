//! Durable publication-effect forwarding under the authority transaction lock.
#![allow(
    clippy::missing_errors_doc,
    dead_code,
    clippy::needless_pass_by_ref_mut,
    clippy::unused_self
)] // Fixture-only durable boundary remains shaped for the owner preflight.

use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationEffectError, PublicationEffectRecovery,
    PublicationEffectScope, ReconcileOutcome,
};
use crate::{Digest, DurableFixturePromotionAuthority};

#[allow(clippy::missing_const_for_fn)] // Owner preflight will make these stateful.
impl DurableFixturePromotionAuthority {
    /// Atomically claim one exact publication scope on the global namespace ledger.
    pub(crate) fn claim_publication_effect(
        &mut self,
        scope: &PublicationEffectScope,
        now: u64,
        revocation_epoch: u64,
        allowlist_generation: u64,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        let _ = (scope, now, revocation_epoch, allowlist_generation);
        policy_unresolved()
    }

    /// Recover an exact persisted claim without mutation.
    pub(crate) fn recover_publication_effect(
        &self,
        scope: &PublicationEffectScope,
    ) -> Result<PublicationEffectRecovery, PublicationEffectError> {
        let _ = scope;
        policy_unresolved()
    }

    pub(crate) fn dispatch_publication_effect(
        &mut self,
        capability: FixturePublicationDispatch,
        now: u64,
        revocation_epoch: u64,
        allowlist_generation: u64,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        let _ = (capability, now, revocation_epoch, allowlist_generation);
        policy_unresolved()
    }

    pub(crate) fn succeed_publication_effect(
        &mut self,
        capability: FixturePublicationDispatch,
        settlement_digest: Digest,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        let _ = (capability, settlement_digest);
        policy_unresolved()
    }

    pub(crate) fn mark_uncertain_publication_effect(
        &mut self,
        capability: FixturePublicationDispatch,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        std::mem::drop(capability);
        policy_unresolved()
    }

    pub(crate) fn reconcile_publication_effect(
        &mut self,
        capability: FixturePublicationDispatch,
        outcome: ReconcileOutcome,
        readback_digest: Digest,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        let _ = (capability, outcome, readback_digest);
        policy_unresolved()
    }

    pub(crate) fn reclaim_publication_effect(
        &mut self,
        capability: FixturePublicationDispatch,
        scope: &PublicationEffectScope,
        now: u64,
        revocation_epoch: u64,
        allowlist_generation: u64,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        let _ = (
            capability,
            scope,
            now,
            revocation_epoch,
            allowlist_generation,
        );
        policy_unresolved()
    }
}

const fn policy_unresolved<T>() -> Result<T, PublicationEffectError> {
    Err(PublicationEffectError::PolicyUnresolved)
}

impl crate::DurableFixturePromotionStore {
    /// Per-promotion durable stores cannot own the global publication namespace ledger.
    #[allow(clippy::missing_const_for_fn)]
    pub(crate) fn claim_publication_effect(
        &self,
        _: &PublicationEffectScope,
        _: u64,
        _: u64,
        _: u64,
    ) -> Result<FixturePublicationDispatch, crate::AuthorityError> {
        Err(crate::AuthorityError::AuthorityNotProvisioned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_facade_is_snapshot_typed() {
        let method: fn(
            &DurableFixturePromotionAuthority,
            &PublicationEffectScope,
        ) -> Result<PublicationEffectRecovery, PublicationEffectError> =
            DurableFixturePromotionAuthority::recover_publication_effect;
        let _ = method;
    }
}
