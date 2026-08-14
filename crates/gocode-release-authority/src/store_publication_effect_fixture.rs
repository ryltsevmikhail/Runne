//! Unit-test-only command engine over the single global authority root.

use crate::DurableFixturePromotionAuthority;
use crate::publication_effect_command::PublicationEffectCommand;
use crate::publication_effect_failpoint::PublicationEffectFailpoint;
use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationEffectError, PublicationEffectExecution,
    PublicationEffectReplay, PublicationEffectScope, PublicationEffectState,
};

impl DurableFixturePromotionAuthority {
    pub(crate) fn arm_publication_failpoint(&self, failpoint: PublicationEffectFailpoint) {
        self.publication_failpoint.set(Some(failpoint));
    }

    pub(crate) fn fixture_claim_publication_command(
        &self,
        command: &PublicationEffectCommand,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load().map_err(durable)?;
        if self.take_publication_failpoint(PublicationEffectFailpoint::BeforeClaimSave) {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        let result = store.publication_effect_ledger.claim_command(command)?;
        if matches!(result, PublicationEffectExecution::Applied(_)) {
            self.save(&store).map_err(durable)?;
            if self.take_publication_failpoint(PublicationEffectFailpoint::AfterClaimSave) {
                return Err(PublicationEffectError::DurableStateUnavailable);
            }
        }
        Ok(result)
    }

    pub(crate) fn fixture_replay_publication_command(
        &self,
        command: &PublicationEffectCommand,
    ) -> Result<PublicationEffectReplay, PublicationEffectError> {
        let _guard = self.lock.borrow();
        self.load()
            .map_err(durable)?
            .publication_effect_ledger
            .replay_command(command)
    }

    pub(crate) fn fixture_dispatch_publication_command(
        &self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let result = self.fixture_mutate(|ledger| ledger.dispatch_command(command, capability))?;
        self.after(PublicationEffectFailpoint::AfterInFlightSave)?;
        Ok(result)
    }

    pub(crate) fn fixture_mark_uncertain_publication_command(
        &self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let result =
            self.fixture_mutate(|ledger| ledger.mark_uncertain_command(command, capability))?;
        self.after(PublicationEffectFailpoint::AfterUncertainSave)?;
        Ok(result)
    }

    pub(crate) fn fixture_succeed_publication_command(
        &self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        self.before(PublicationEffectFailpoint::BeforeSettlementSave)?;
        let result = self.fixture_mutate(|ledger| ledger.succeed_command(command, capability))?;
        self.after(PublicationEffectFailpoint::AfterSettlementSave)?;
        Ok(result)
    }

    pub(crate) fn fixture_reconcile_publication_command(
        &self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let result = self.fixture_mutate(|ledger| ledger.reconcile_command(command, capability))?;
        self.after(PublicationEffectFailpoint::AfterReconcileSave)?;
        Ok(result)
    }

    pub(crate) fn fixture_mark_response_lost(
        &self,
        id: &str,
        scope: &PublicationEffectScope,
    ) -> Result<PublicationEffectReplay, PublicationEffectError> {
        let command;
        let replay;
        {
            let _guard = self.lock.borrow_mut();
            let mut store = self.load().map_err(durable)?;
            if store
                .publication_effect_ledger
                .scope_for_namespace(&scope.idempotency_namespace)?
                != scope
            {
                return Err(PublicationEffectError::DivergentClaim);
            }
            let capability = store.publication_effect_ledger.response_loss_capability(
                &scope.idempotency_namespace,
                PublicationEffectState::InFlight,
            )?;
            command = PublicationEffectCommand::mark_uncertain(id, scope, &capability);
            store
                .publication_effect_ledger
                .mark_uncertain_command(&command, capability)?;
            replay = store.publication_effect_ledger.replay_command(&command)?;
            self.save(&store).map_err(durable)?;
        }
        Ok(replay)
    }

    pub(crate) fn fixture_reclaim_after_absence(
        &self,
        id: &str,
        scope: &PublicationEffectScope,
        context: crate::publication_effect_command::PublicationEffectContext,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load().map_err(durable)?;
        let capability = store.publication_effect_ledger.response_loss_capability(
            &scope.idempotency_namespace,
            PublicationEffectState::ReconciledAbsent,
        )?;
        let command = PublicationEffectCommand::reclaim(id, scope, context, &capability);
        let result = store
            .publication_effect_ledger
            .reclaim_command(&command, capability)?;
        self.save(&store).map_err(durable)?;
        Ok(result)
    }

    pub(crate) fn take_publication_failpoint(&self, expected: PublicationEffectFailpoint) -> bool {
        if self.publication_failpoint.get() == Some(expected) {
            self.publication_failpoint.set(None);
            true
        } else {
            false
        }
    }

    fn fixture_mutate(
        &self,
        apply: impl FnOnce(
            &mut crate::publication_effect_ledger::FixturePublicationEffectLedger,
        ) -> Result<PublicationEffectExecution, PublicationEffectError>,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load().map_err(durable)?;
        let result = apply(&mut store.publication_effect_ledger)?;
        self.save(&store).map_err(durable)?;
        Ok(result)
    }

    fn before(&self, failpoint: PublicationEffectFailpoint) -> Result<(), PublicationEffectError> {
        (!self.take_publication_failpoint(failpoint))
            .then_some(())
            .ok_or(PublicationEffectError::DurableStateUnavailable)
    }

    fn after(&self, failpoint: PublicationEffectFailpoint) -> Result<(), PublicationEffectError> {
        self.before(failpoint)
    }
}

const fn durable(_: crate::AuthorityError) -> PublicationEffectError {
    PublicationEffectError::DurableStateUnavailable
}
