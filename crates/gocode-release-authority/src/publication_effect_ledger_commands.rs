//! Command-aware publication-effect execution and exact replay.
#![allow(clippy::missing_errors_doc, dead_code, clippy::redundant_pub_crate)]

use crate::Digest;
use crate::publication_effect_command::{
    PublicationEffectCommand, capability_digest, outcome_state,
};
use crate::publication_effect_ledger::{FixturePublicationEffectLedger, PublicationCommandRecord};
use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationEffectError, PublicationEffectExecution,
    PublicationEffectReplay, PublicationEffectScope, PublicationEffectState,
};

impl FixturePublicationEffectLedger {
    pub(crate) fn claim_command(
        &mut self,
        command: &PublicationEffectCommand,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        if !matches!(command, PublicationEffectCommand::Claim { .. }) {
            return Err(PublicationEffectError::InvalidState);
        }
        let fingerprint = command.fingerprint()?;
        if let Some(replay) = self.replay_known(command, fingerprint)? {
            return Ok(PublicationEffectExecution::Replayed(replay));
        }
        let (context, scope) = command_context(command)?;
        let raw = self.claim(
            scope,
            context.observed_at,
            context.revocation_epoch,
            context.allowlist_generation,
        )?;
        let capability = with_capability(raw, capability_digest(scope, fingerprint));
        self.record(command, fingerprint, PublicationEffectState::Claimed, None)?;
        Ok(PublicationEffectExecution::Applied(capability))
    }

    pub(crate) fn dispatch_command(
        &mut self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let fingerprint = command.fingerprint()?;
        self.require_new(command, fingerprint)?;
        let (context, scope, expected) = dispatch_parts(command)?;
        self.require_exact_live(scope, expected, &capability)?;
        let capability = self.dispatch(
            capability,
            context.observed_at,
            context.revocation_epoch,
            context.allowlist_generation,
        )?;
        self.record(command, fingerprint, PublicationEffectState::InFlight, None)?;
        Ok(PublicationEffectExecution::Applied(with_capability(
            capability, expected,
        )))
    }

    pub(crate) fn mark_uncertain_command(
        &mut self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let fingerprint = command.fingerprint()?;
        self.require_new(command, fingerprint)?;
        let (scope, expected) = capability_parts(command)?;
        self.require_exact_live(scope, expected, &capability)?;
        let capability = self.mark_uncertain(capability)?;
        self.record(
            command,
            fingerprint,
            PublicationEffectState::Uncertain,
            None,
        )?;
        Ok(PublicationEffectExecution::Applied(with_capability(
            capability, expected,
        )))
    }

    pub(crate) fn succeed_command(
        &mut self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let fingerprint = command.fingerprint()?;
        self.require_new(command, fingerprint)?;
        let (scope, expected, evidence) = evidence_parts(command)?;
        self.require_exact_live(scope, expected, &capability)?;
        let capability = self.succeed(capability, evidence)?;
        self.record(
            command,
            fingerprint,
            PublicationEffectState::Succeeded,
            Some(evidence),
        )?;
        Ok(PublicationEffectExecution::Applied(with_capability(
            capability, expected,
        )))
    }

    pub(crate) fn reconcile_command(
        &mut self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let fingerprint = command.fingerprint()?;
        self.require_new(command, fingerprint)?;
        let PublicationEffectCommand::Reconcile {
            scope,
            capability: expected,
            result,
            evidence,
            ..
        } = command
        else {
            return Err(PublicationEffectError::InvalidState);
        };
        self.require_exact_live(scope, *expected, &capability)?;
        let capability = self.reconcile(capability, *result, *evidence)?;
        self.record(
            command,
            fingerprint,
            outcome_state(*result),
            Some(*evidence),
        )?;
        Ok(PublicationEffectExecution::Applied(with_capability(
            capability, *expected,
        )))
    }

    pub(crate) fn reclaim_command(
        &mut self,
        command: &PublicationEffectCommand,
        capability: FixturePublicationDispatch,
    ) -> Result<PublicationEffectExecution, PublicationEffectError> {
        let fingerprint = command.fingerprint()?;
        self.require_new(command, fingerprint)?;
        let (context, scope, expected) = dispatch_parts(command)?;
        self.require_exact_reclaim(scope, expected, &capability)?;
        let capability = self.reclaim(
            capability,
            scope,
            context.observed_at,
            context.revocation_epoch,
            context.allowlist_generation,
        )?;
        let next = capability_digest(scope, fingerprint);
        self.record(command, fingerprint, PublicationEffectState::Claimed, None)?;
        Ok(PublicationEffectExecution::Applied(with_capability(
            capability, next,
        )))
    }

    pub(crate) fn replay_command(
        &self,
        command: &PublicationEffectCommand,
    ) -> Result<PublicationEffectReplay, PublicationEffectError> {
        let fingerprint = command.fingerprint()?;
        self.replay_known(command, fingerprint)?
            .ok_or(PublicationEffectError::InvalidState)
    }
    fn require_new(
        &self,
        command: &PublicationEffectCommand,
        fingerprint: Digest,
    ) -> Result<(), PublicationEffectError> {
        if self.replay_known(command, fingerprint)?.is_some() {
            return Err(PublicationEffectError::InvalidState);
        }
        Ok(())
    }
    fn replay_known(
        &self,
        command: &PublicationEffectCommand,
        fingerprint: Digest,
    ) -> Result<Option<PublicationEffectReplay>, PublicationEffectError> {
        let known = self
            .bindings
            .values()
            .flat_map(|binding| &binding.commands)
            .find(|record| record.command.id() == command.id());
        known.map_or(Ok(None), |record| {
            (record.fingerprint == fingerprint)
                .then(|| record.outcome.clone())
                .ok_or(PublicationEffectError::CommandReplayDiverged)
                .map(Some)
        })
    }
    fn record(
        &mut self,
        command: &PublicationEffectCommand,
        fingerprint: Digest,
        state: PublicationEffectState,
        evidence: Option<Digest>,
    ) -> Result<(), PublicationEffectError> {
        let scope = command.scope();
        let binding = self
            .bindings
            .get_mut(&scope.idempotency_namespace)
            .ok_or(PublicationEffectError::InvalidState)?;
        binding.commands.push(PublicationCommandRecord {
            command: command.clone(),
            fingerprint,
            outcome: PublicationEffectReplay {
                command_fingerprint: fingerprint,
                state,
                generation: scope.generation,
                evidence,
            },
        });
        Ok(())
    }
}

const fn command_context(
    command: &PublicationEffectCommand,
) -> Result<
    (
        &crate::publication_effect_command::PublicationEffectContext,
        &PublicationEffectScope,
    ),
    PublicationEffectError,
> {
    match command {
        PublicationEffectCommand::Claim { scope, context, .. }
        | PublicationEffectCommand::Dispatch { scope, context, .. }
        | PublicationEffectCommand::Reclaim { scope, context, .. } => Ok((context, scope)),
        _ => Err(PublicationEffectError::InvalidState),
    }
}
const fn dispatch_parts(
    command: &PublicationEffectCommand,
) -> Result<
    (
        &crate::publication_effect_command::PublicationEffectContext,
        &PublicationEffectScope,
        Digest,
    ),
    PublicationEffectError,
> {
    match command {
        PublicationEffectCommand::Dispatch {
            scope,
            context,
            capability,
            ..
        }
        | PublicationEffectCommand::Reclaim {
            scope,
            context,
            capability,
            ..
        } => Ok((context, scope, *capability)),
        _ => Err(PublicationEffectError::InvalidState),
    }
}
const fn capability_parts(
    command: &PublicationEffectCommand,
) -> Result<(&PublicationEffectScope, Digest), PublicationEffectError> {
    match command {
        PublicationEffectCommand::MarkUncertain {
            scope, capability, ..
        } => Ok((scope, *capability)),
        _ => Err(PublicationEffectError::InvalidState),
    }
}
const fn evidence_parts(
    command: &PublicationEffectCommand,
) -> Result<(&PublicationEffectScope, Digest, Digest), PublicationEffectError> {
    match command {
        PublicationEffectCommand::SucceedSettlement {
            scope,
            capability,
            evidence,
            ..
        } => Ok((scope, *capability, *evidence)),
        _ => Err(PublicationEffectError::InvalidState),
    }
}
const fn with_capability(
    mut capability: FixturePublicationDispatch,
    digest: Digest,
) -> FixturePublicationDispatch {
    capability.0.capability = digest;
    capability
}
