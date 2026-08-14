//! Canonical publication-effect ledger codec and semantic reconstruction.

use crate::Digest;
use crate::publication_effect_durable_wire::{
    ClaimWire, CommandRecordWire, LedgerWire, OutcomeWire,
};
use crate::publication_effect_intent::{PublicationEffectIntentWire, decode_intent, digest};
use crate::publication_effect_ledger::{
    FixturePublicationEffectLedger, PublicationClaimBinding, PublicationCommandRecord,
};
use crate::publication_effect_types::{
    PublicationEffectError, PublicationEffectReplay, PublicationEffectState,
};

#[path = "publication_effect_durable_codec_command.rs"]
mod command;
#[path = "publication_effect_durable_codec_validation.rs"]
mod validation;

use super::SCHEMA;

pub(crate) fn encode_ledger(
    ledger: &FixturePublicationEffectLedger,
) -> Result<Vec<u8>, PublicationEffectError> {
    validation::validate(ledger)?;
    let claims = ledger
        .bindings
        .iter()
        .map(|(namespace, binding)| ClaimWire {
            namespace: namespace.clone(),
            intent: PublicationEffectIntentWire::from(&binding.scope),
            state: state(binding.state).into(),
            reconciliations: binding.reconciliations,
            settlement_sha256: binding.settlement.map(Digest::to_hex),
            commands: binding.commands.iter().map(record_to_wire).collect(),
        })
        .collect();
    let value = serde_json::to_value(LedgerWire {
        schema_version: SCHEMA.into(),
        claims,
    })
    .map_err(|_| corrupt())?;
    let mut bytes = serde_json::to_vec(&crate::wire::sorted_value(value)).map_err(|_| corrupt())?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn decode_ledger(
    bytes: &[u8],
) -> Result<FixturePublicationEffectLedger, PublicationEffectError> {
    let value = crate::wire::strict_json::parse(bytes).map_err(|_| corrupt())?;
    let wire: LedgerWire = serde_json::from_value(value).map_err(|_| corrupt())?;
    if wire.schema_version != SCHEMA {
        return Err(corrupt());
    }
    let mut ledger = FixturePublicationEffectLedger::default();
    for claim in wire.claims {
        let scope = decode_intent(claim.intent)?;
        if claim.namespace != scope.idempotency_namespace
            || ledger.bindings.contains_key(&claim.namespace)
        {
            return Err(corrupt());
        }
        let commands = claim
            .commands
            .into_iter()
            .map(record_from_wire)
            .collect::<Result<Vec<_>, _>>()?;
        ledger.bindings.insert(
            claim.namespace,
            PublicationClaimBinding {
                scope,
                state: parse_state(&claim.state)?,
                reconciliations: claim.reconciliations,
                settlement: claim.settlement_sha256.as_deref().map(digest).transpose()?,
                commands,
            },
        );
    }
    validation::validate(&ledger)?;
    (encode_ledger(&ledger)? == bytes)
        .then_some(ledger)
        .ok_or_else(corrupt)
}

fn record_to_wire(record: &PublicationCommandRecord) -> CommandRecordWire {
    CommandRecordWire {
        command: command::to_wire(&record.command),
        command_fingerprint_sha256: record.fingerprint.to_hex(),
        outcome: OutcomeWire {
            state: state(record.outcome.state).into(),
            generation: record.outcome.generation,
            evidence_sha256: record.outcome.evidence.map(Digest::to_hex),
        },
    }
}

fn record_from_wire(
    value: CommandRecordWire,
) -> Result<PublicationCommandRecord, PublicationEffectError> {
    let command = command::from_wire(value.command)?;
    let fingerprint = digest(&value.command_fingerprint_sha256)?;
    Ok(PublicationCommandRecord {
        command,
        fingerprint,
        outcome: PublicationEffectReplay {
            command_fingerprint: fingerprint,
            state: parse_state(&value.outcome.state)?,
            generation: value.outcome.generation,
            evidence: value
                .outcome
                .evidence_sha256
                .as_deref()
                .map(digest)
                .transpose()?,
        },
    })
}

const fn state(value: PublicationEffectState) -> &'static str {
    match value {
        PublicationEffectState::Authorized => "authorized",
        PublicationEffectState::Claimed => "claimed",
        PublicationEffectState::InFlight => "in_flight",
        PublicationEffectState::Succeeded => "succeeded",
        PublicationEffectState::Uncertain => "uncertain",
        PublicationEffectState::ReconciledSucceeded => "reconciled_succeeded",
        PublicationEffectState::ReconciledAbsent => "reconciled_absent",
        PublicationEffectState::Blocked => "blocked",
    }
}
fn parse_state(value: &str) -> Result<PublicationEffectState, PublicationEffectError> {
    match value {
        "claimed" => Ok(PublicationEffectState::Claimed),
        "in_flight" => Ok(PublicationEffectState::InFlight),
        "succeeded" => Ok(PublicationEffectState::Succeeded),
        "uncertain" => Ok(PublicationEffectState::Uncertain),
        "reconciled_succeeded" => Ok(PublicationEffectState::ReconciledSucceeded),
        "reconciled_absent" => Ok(PublicationEffectState::ReconciledAbsent),
        "blocked" => Ok(PublicationEffectState::Blocked),
        _ => Err(corrupt()),
    }
}
const fn corrupt() -> PublicationEffectError {
    PublicationEffectError::DurableStateUnavailable
}
