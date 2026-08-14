//! Shared scalar promotion transitions for fixture stores.

use crate::store::CommandFingerprint;
use crate::{AuthorityError, CommandId, Mutation, PromotionId, PromotionState, TransactionOutcome};

pub fn completed(
    record: &crate::store_machine::Record,
    _id: &PromotionId,
    expected: u64,
    command: &CommandId,
    bundle: &crate::FixturePrevalidatedSignedBundle,
) -> Result<TransactionOutcome, AuthorityError> {
    if bundle.authority_instance() != record.authority_instance
        || record.completed_verify.get(command.as_str()) != Some(&(expected, bundle.commitment()))
    {
        return Err(AuthorityError::CommandReplayDiverged);
    }
    record
        .commands
        .get(command.as_str())
        .map(|(_, outcome)| outcome.clone())
        .ok_or(AuthorityError::InvalidTransition)
}

pub fn transact(
    record: &mut crate::store_machine::Record,
    id: &PromotionId,
    expected: u64,
    command: CommandId,
    mutation: Mutation,
) -> Result<TransactionOutcome, AuthorityError> {
    transact_inner(record, id, expected, command, mutation, false)
}

pub fn transact_bound_stage(
    record: &mut crate::store_machine::Record,
    id: &PromotionId,
    expected: u64,
    command: CommandId,
    mutation: Mutation,
) -> Result<TransactionOutcome, AuthorityError> {
    transact_inner(record, id, expected, command, mutation, true)
}

fn transact_inner(
    record: &mut crate::store_machine::Record,
    id: &PromotionId,
    expected: u64,
    command: CommandId,
    mutation: Mutation,
    bound_stage: bool,
) -> Result<TransactionOutcome, AuthorityError> {
    crate::store_command::require_canonical(&command)?;
    if !bound_stage
        && matches!(
            &mutation,
            Mutation::QualifyUnsigned { .. } | Mutation::FixtureAuthorizeSigning { .. }
        )
    {
        return Err(AuthorityError::InvalidTransition);
    }
    let fingerprint = crate::store_command::fingerprint(expected, &mutation);
    if let Some((known, outcome)) = record.commands.get(command.as_str()) {
        return if *known == fingerprint {
            Ok(outcome.clone())
        } else {
            Err(AuthorityError::CommandReplayDiverged)
        };
    }
    if record.revision != expected {
        return Err(AuthorityError::StaleRevision);
    }
    if record.threshold_outbox.is_some() {
        return Err(AuthorityError::BindingMismatch);
    }
    if let Mutation::VerifySigned { proof } = &mutation
        && !proof.matches_command(&command)
    {
        return Err(AuthorityError::CommandReplayDiverged);
    }
    if let Mutation::FixtureAuthorizePublication { bundle } = &mutation
        && (bundle.promotion() != id || bundle.revision() != expected)
    {
        return Err(AuthorityError::BindingMismatch);
    }
    if record.revision == u64::MAX {
        return Err(AuthorityError::StaleRevision);
    }
    let mut next = record.clone();
    crate::store_machine::apply(&mut next, mutation)?;
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(AuthorityError::StaleRevision)?;
    next.previous_snapshot = next.snapshot.as_ref().map(|snapshot| snapshot.digest);
    next.snapshot = Some(crate::store_snapshot::build(id, &next, fingerprint)?);
    let outcome = TransactionOutcome {
        state: next.state.ok_or(AuthorityError::InvalidTransition)?,
        revision: next.revision,
        fixture: true,
    };
    next.commands
        .insert(command.into_inner(), (fingerprint, outcome.clone()));
    *record = next;
    Ok(outcome)
}

pub fn begin_ack(
    record: &mut crate::store_machine::Record,
    id: &PromotionId,
    expected: u64,
    command: &CommandId,
) -> Result<(crate::PendingThresholdAck, CommandFingerprint), AuthorityError> {
    crate::store_command::require_canonical(command)?;
    if let Some(tombstone) = &record.threshold_ack {
        let fingerprint = crate::store_command::threshold_ack_fingerprint(
            id,
            expected,
            command,
            tombstone.admission,
        );
        return (tombstone.claim_revision == expected
            && tombstone.command == command.as_str()
            && tombstone.fingerprint == fingerprint)
            .then_some({
                (
                    crate::PendingThresholdAck {
                        admission: tombstone.admission,
                        revision: expected,
                    },
                    fingerprint,
                )
            })
            .ok_or(AuthorityError::CommandReplayDiverged);
    }
    let delivery = record
        .threshold_outbox
        .as_ref()
        .ok_or(AuthorityError::BindingMismatch)?;
    let (admission, claim_revision) = delivery.claim();
    let fingerprint =
        crate::store_command::threshold_ack_fingerprint(id, expected, command, admission);
    if let crate::store_stage_trust::ThresholdAckDelivery::Delivering {
        command: claimed, ..
    } = delivery
        && claimed != command.as_str()
    {
        return Err(AuthorityError::CommandReplayDiverged);
    }
    if record.revision != expected
        || claim_revision != expected
        || record.state != Some(PromotionState::SignedEnvelopesVerified)
    {
        return Err(if record.revision == expected {
            AuthorityError::BindingMismatch
        } else {
            AuthorityError::StaleRevision
        });
    }
    let claim = crate::PendingThresholdAck {
        admission,
        revision: expected,
    };
    record.threshold_outbox = Some(crate::store_stage_trust::ThresholdAckDelivery::Delivering {
        admission,
        revision: expected,
        command: command.as_str().into(),
    });
    Ok((claim, fingerprint))
}
pub fn settle_ack(
    record: &mut crate::store_machine::Record,
    id: &PromotionId,
    command: CommandId,
    claim: crate::PendingThresholdAck,
    proof: crate::ThresholdAckProof,
    fingerprint: CommandFingerprint,
) -> Result<TransactionOutcome, AuthorityError> {
    let delivery = record
        .threshold_outbox
        .as_ref()
        .ok_or(AuthorityError::BindingMismatch)?;
    let (admission, revision) = claim.into_parts();
    if !matches!(
        delivery,
        crate::store_stage_trust::ThresholdAckDelivery::Delivering { .. }
    ) || delivery.claim() != (admission, revision)
        || !proof.matches(admission, revision)
        || record.revision != revision
        || record.threshold_ack.is_some()
    {
        return Err(AuthorityError::BindingMismatch);
    }
    let mut next = record.clone();
    next.threshold_outbox = None;
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(AuthorityError::StaleRevision)?;
    next.previous_snapshot = next.snapshot.as_ref().map(|snapshot| snapshot.digest);
    next.snapshot = Some(crate::store_snapshot::build(id, &next, fingerprint)?);
    let outcome = TransactionOutcome {
        state: next.state.ok_or(AuthorityError::InvalidTransition)?,
        revision: next.revision,
        fixture: true,
    };
    let command_name = command.into_inner();
    next.commands
        .insert(command_name.clone(), (fingerprint, outcome.clone()));
    next.threshold_ack = Some(crate::store_stage_trust::ThresholdAckTombstone {
        admission,
        claim_revision: revision,
        command: command_name,
        fingerprint,
        outcome: outcome.clone(),
    });
    *record = next;
    Ok(outcome)
}
