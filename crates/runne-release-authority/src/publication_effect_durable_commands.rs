//! Persist-before-return command execution for the durable fixture ledger.
#![allow(clippy::missing_errors_doc, dead_code)]

use crate::publication_effect_command::PublicationEffectCommand;
use crate::publication_effect_durable::DurableFixturePublicationEffectLedger;
use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationEffectError, PublicationEffectExecution,
    PublicationEffectReplay, PublicationEffectScope, PublicationEffectState,
};

impl DurableFixturePublicationEffectLedger {
    pub(crate) fn claim_command(
        &mut self,
        command: &PublicationEffectCommand,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        #[cfg(test)]
        if self.take_failpoint(
            crate::publication_effect_failpoint::PublicationEffectFailpoint::BeforeClaimSave,
        ) {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        let mut staged = self.ledger.clone();
        let result = staged.claim_command(command)?;
        if matches!(result, PublicationEffectExecution::Applied(_)) {
            self.save(&staged)?;
            self.ledger = staged;
            #[cfg(test)]
            if self.take_failpoint(
                crate::publication_effect_failpoint::PublicationEffectFailpoint::AfterClaimSave,
            ) {
                return Err(PublicationEffectError::DurableStateUnavailable);
            }
        }
        Ok(result)
    }
    pub(crate) fn dispatch_command(
        &mut self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let result = self.mutate(|ledger| ledger.dispatch_command(command, capability))?;
        #[cfg(test)]
        if self.take_failpoint(
            crate::publication_effect_failpoint::PublicationEffectFailpoint::AfterInFlightSave,
        ) {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        Ok(result)
    }
    pub(crate) fn mark_uncertain_command(
        &mut self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let result = self.mutate(|ledger| ledger.mark_uncertain_command(command, capability))?;
        #[cfg(test)]
        if self.take_failpoint(
            crate::publication_effect_failpoint::PublicationEffectFailpoint::AfterUncertainSave,
        ) {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        Ok(result)
    }
    pub(crate) fn succeed_command(
        &mut self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        #[cfg(test)]
        if self.take_failpoint(
            crate::publication_effect_failpoint::PublicationEffectFailpoint::BeforeSettlementSave,
        ) {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        let result = self.mutate(|ledger| ledger.succeed_command(command, capability))?;
        #[cfg(test)]
        if self.take_failpoint(
            crate::publication_effect_failpoint::PublicationEffectFailpoint::AfterSettlementSave,
        ) {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        Ok(result)
    }
    pub(crate) fn reconcile_command(
        &mut self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let result = self.mutate(|ledger| ledger.reconcile_command(command, capability))?;
        #[cfg(test)]
        if self.take_failpoint(
            crate::publication_effect_failpoint::PublicationEffectFailpoint::AfterReconcileSave,
        ) {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        Ok(result)
    }
    pub(crate) fn reclaim_command(
        &mut self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        self.mutate(|ledger| ledger.reclaim_command(command, capability))
    }
    pub(crate) fn replay_command(
        &self,
        command: &PublicationEffectCommand,
    ) -> Result<PublicationEffectReplay, PublicationEffectError> {
        if self.is_poisoned() {
            return Err(PublicationEffectError::DurableStateUnavailable);
        }
        self.ledger.replay_command(command)
    }

    pub(crate) fn mark_response_lost(
        &mut self,
        id: &str,
        scope: &PublicationEffectScope,
    ) -> Result<PublicationEffectReplay, PublicationEffectError> {
        if self.ledger.scope_for_namespace(&scope.idempotency_namespace)? != scope {
            return Err(PublicationEffectError::DivergentClaim);
        }
        let capability = self.ledger.response_loss_capability(
            &scope.idempotency_namespace,
            PublicationEffectState::InFlight,
        )?;
        let command = crate::publication_effect_command::PublicationEffectCommand::mark_uncertain(
            id,
            scope,
            &capability,
        );
        self.mark_uncertain_command(&command, capability)?;
        self.replay_command(&command)
    }

    pub(crate) fn reclaim_after_absence(
        &mut self,
        id: &str,
        scope: &PublicationEffectScope,
        context: crate::publication_effect_command::PublicationEffectContext,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let capability = self.ledger.response_loss_capability(
            &scope.idempotency_namespace,
            PublicationEffectState::ReconciledAbsent,
        )?;
        let command = crate::publication_effect_command::PublicationEffectCommand::reclaim(
            id,
            scope,
            context,
            &capability,
        );
        self.reclaim_command(&command, capability)
    }
    fn mutate(
        &mut self,
        apply: impl FnOnce(
            &mut crate::publication_effect_ledger::FixturePublicationEffectLedger,
        ) -> Result<PublicationEffectExecution, PublicationEffectError>,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let mut staged = self.ledger.clone();
        let result = apply(&mut staged)?;
        self.save(&staged)?;
        self.ledger = staged;
        Ok(result)
    }
}
