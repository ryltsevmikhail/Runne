//! Canonical command wire conversion.

use crate::publication_effect_command::{PublicationEffectCommand, PublicationEffectContext};
use crate::publication_effect_durable_wire::CommandWire;
use crate::publication_effect_intent::{PublicationEffectIntentWire, decode_intent, digest};
use crate::publication_effect_types::{PublicationEffectError, ReconcileOutcome};

pub(super) fn to_wire(command: &PublicationEffectCommand) -> CommandWire {
    let intent = || PublicationEffectIntentWire::from(command.scope());
    match command {
        PublicationEffectCommand::Claim { id, context, .. } => CommandWire::Claim {
            command_id: id.clone(),
            intent: intent(),
            observed_at: context.observed_at,
            current_revocation_epoch: context.revocation_epoch,
            current_allowlist_generation: context.allowlist_generation,
        },
        PublicationEffectCommand::Dispatch {
            id,
            context,
            capability,
            ..
        } => CommandWire::Dispatch {
            command_id: id.clone(),
            intent: intent(),
            capability_sha256: capability.to_hex(),
            observed_at: context.observed_at,
            current_revocation_epoch: context.revocation_epoch,
            current_allowlist_generation: context.allowlist_generation,
        },
        PublicationEffectCommand::MarkUncertain { id, capability, .. } => {
            CommandWire::MarkUncertain {
                command_id: id.clone(),
                intent: intent(),
                capability_sha256: capability.to_hex(),
            }
        }
        PublicationEffectCommand::SucceedSettlement {
            id,
            capability,
            evidence,
            ..
        } => CommandWire::SucceedSettlement {
            command_id: id.clone(),
            intent: intent(),
            capability_sha256: capability.to_hex(),
            evidence_sha256: evidence.to_hex(),
        },
        PublicationEffectCommand::Reconcile {
            id,
            capability,
            result,
            evidence,
            ..
        } => reconcile_wire(id, intent(), *capability, *evidence, *result),
        PublicationEffectCommand::Reclaim {
            id,
            context,
            capability,
            ..
        } => CommandWire::Reclaim {
            command_id: id.clone(),
            intent: intent(),
            capability_sha256: capability.to_hex(),
            observed_at: context.observed_at,
            current_revocation_epoch: context.revocation_epoch,
            current_allowlist_generation: context.allowlist_generation,
        },
    }
}

fn reconcile_wire(
    id: &str,
    intent: PublicationEffectIntentWire,
    capability: crate::Digest,
    evidence: crate::Digest,
    result: ReconcileOutcome,
) -> CommandWire {
    let command_id = id.into();
    let capability_sha256 = capability.to_hex();
    let evidence_sha256 = evidence.to_hex();
    match result {
        ReconcileOutcome::Succeeded => CommandWire::ReconcileSucceeded {
            command_id,
            intent,
            capability_sha256,
            evidence_sha256,
        },
        ReconcileOutcome::Absent => CommandWire::ReconcileAbsent {
            command_id,
            intent,
            capability_sha256,
            evidence_sha256,
        },
        ReconcileOutcome::Inconclusive => CommandWire::ReconcileInconclusive {
            command_id,
            intent,
            capability_sha256,
            evidence_sha256,
        },
    }
}

pub(super) fn from_wire(
    value: CommandWire,
) -> Result<PublicationEffectCommand, PublicationEffectError> {
    Ok(match value {
        CommandWire::Claim {
            command_id,
            intent,
            observed_at,
            current_revocation_epoch,
            current_allowlist_generation,
        } => contextual(
            command_id,
            intent,
            None,
            observed_at,
            current_revocation_epoch,
            current_allowlist_generation,
            false,
        )?,
        CommandWire::Dispatch {
            command_id,
            intent,
            capability_sha256,
            observed_at,
            current_revocation_epoch,
            current_allowlist_generation,
        } => contextual(
            command_id,
            intent,
            Some(capability_sha256),
            observed_at,
            current_revocation_epoch,
            current_allowlist_generation,
            false,
        )?,
        CommandWire::Reclaim {
            command_id,
            intent,
            capability_sha256,
            observed_at,
            current_revocation_epoch,
            current_allowlist_generation,
        } => contextual(
            command_id,
            intent,
            Some(capability_sha256),
            observed_at,
            current_revocation_epoch,
            current_allowlist_generation,
            true,
        )?,
        CommandWire::MarkUncertain {
            command_id,
            intent,
            capability_sha256,
        } => mark_uncertain(command_id, intent, &capability_sha256)?,
        CommandWire::SucceedSettlement {
            command_id,
            intent,
            capability_sha256,
            evidence_sha256,
        } => succeed(command_id, intent, &capability_sha256, &evidence_sha256)?,
        CommandWire::ReconcileSucceeded {
            command_id,
            intent,
            capability_sha256,
            evidence_sha256,
        } => reconcile(
            command_id,
            intent,
            &capability_sha256,
            &evidence_sha256,
            ReconcileOutcome::Succeeded,
        )?,
        CommandWire::ReconcileAbsent {
            command_id,
            intent,
            capability_sha256,
            evidence_sha256,
        } => reconcile(
            command_id,
            intent,
            &capability_sha256,
            &evidence_sha256,
            ReconcileOutcome::Absent,
        )?,
        CommandWire::ReconcileInconclusive {
            command_id,
            intent,
            capability_sha256,
            evidence_sha256,
        } => reconcile(
            command_id,
            intent,
            &capability_sha256,
            &evidence_sha256,
            ReconcileOutcome::Inconclusive,
        )?,
    })
}

fn contextual(
    id: String,
    intent: PublicationEffectIntentWire,
    capability: Option<String>,
    observed_at: u64,
    revocation_epoch: u64,
    allowlist_generation: u64,
    reclaim: bool,
) -> Result<PublicationEffectCommand, PublicationEffectError> {
    let scope = decode_intent(intent)?;
    let context = PublicationEffectContext {
        observed_at,
        revocation_epoch,
        allowlist_generation,
    };
    match capability {
        None => Ok(PublicationEffectCommand::Claim { id, scope, context }),
        Some(value) if reclaim => Ok(PublicationEffectCommand::Reclaim {
            id,
            scope,
            context,
            capability: digest(&value)?,
        }),
        Some(value) => Ok(PublicationEffectCommand::Dispatch {
            id,
            scope,
            context,
            capability: digest(&value)?,
        }),
    }
}

fn reconcile(
    id: String,
    intent: PublicationEffectIntentWire,
    capability: &str,
    evidence: &str,
    result: ReconcileOutcome,
) -> Result<PublicationEffectCommand, PublicationEffectError> {
    Ok(PublicationEffectCommand::Reconcile {
        id,
        scope: decode_intent(intent)?,
        capability: digest(capability)?,
        result,
        evidence: digest(evidence)?,
    })
}

fn mark_uncertain(
    id: String,
    intent: PublicationEffectIntentWire,
    capability: &str,
) -> Result<PublicationEffectCommand, PublicationEffectError> {
    Ok(PublicationEffectCommand::MarkUncertain {
        id,
        scope: decode_intent(intent)?,
        capability: digest(capability)?,
    })
}

fn succeed(
    id: String,
    intent: PublicationEffectIntentWire,
    capability: &str,
    evidence: &str,
) -> Result<PublicationEffectCommand, PublicationEffectError> {
    Ok(PublicationEffectCommand::SucceedSettlement {
        id,
        scope: decode_intent(intent)?,
        capability: digest(capability)?,
        evidence: digest(evidence)?,
    })
}
