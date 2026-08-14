use super::{FileState, RecordWire};
use crate::{AuthorityError, PromotionState, store_machine::Record};

pub(super) fn validate(file: &FileState, record: &Record) -> Result<(), AuthorityError> {
    let wire = &file.record;
    valid_trust(wire)?;
    valid_commands(record)?;
    valid_reservations(&file.promotion, wire, record)?;
    valid_stage_shape(wire, record)?;
    super::stage_claims::validate(&file.promotion, wire, record)?;
    valid_threshold(record)?;
    valid_publication(wire, record)
}

fn valid_stage_shape(wire: &RecordWire, record: &Record) -> Result<(), AuthorityError> {
    let state = record.state.ok_or(AuthorityError::BindingMismatch)?;
    let valid = wire.admission.is_some()
        && record.authority_instance != crate::Digest::from_bytes([0; 32])
        && record.admission_facts.is_some()
        && match state {
            PromotionState::Rc0Ingested | PromotionState::Rc1Review => {
                record.rc1.is_none() && record.rc2.is_none()
            }
            PromotionState::QualifiedUnsigned => record.rc1.is_some() && record.rc2.is_none(),
            PromotionState::SigningAuthorized
            | PromotionState::SignedEnvelopesVerified
            | PromotionState::Rc3Review
            | PromotionState::PublicationAuthorized => record.rc1.is_some() && record.rc2.is_some(),
        };
    if record
        .rc2_effect_authorization
        .as_ref()
        .is_some_and(|authorization| {
            authorization.fixture().authority_instance != record.authority_instance
        })
    {
        return Err(AuthorityError::BindingMismatch);
    }
    valid.then_some(()).ok_or(AuthorityError::BindingMismatch)
}

fn valid_trust(wire: &RecordWire) -> Result<(), AuthorityError> {
    (canonical_time(&wire.stage_trust_utc)
        && wire.stage_trust_root_epoch > 0
        && wire.stage_trust_role_floor > 0)
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)
}

fn valid_commands(record: &Record) -> Result<(), AuthorityError> {
    record
        .commands
        .iter()
        .all(|(command, (_, outcome))| {
            canonical_id(command)
                && outcome.revision > 0
                && outcome.revision <= record.revision
                && outcome.fixture
        })
        .then_some(())
        .ok_or(AuthorityError::BindingMismatch)
}

fn valid_reservations(id: &str, wire: &RecordWire, record: &Record) -> Result<(), AuthorityError> {
    if let Some(value) = &wire.reservation {
        let valid = value.promotion == id
            && value.revision == record.revision
            && canonical_id(&value.command)
            && record.state == Some(PromotionState::SigningAuthorized)
            && record.rc2.is_some()
            && !record.commands.contains_key(&value.command);
        if !valid {
            return Err(AuthorityError::BindingMismatch);
        }
    }
    if let Some(value) = &wire.stage_reservation {
        let expected = match value.kind.as_str() {
            "rc1" => PromotionState::Rc1Review,
            "rc2" => PromotionState::QualifiedUnsigned,
            "rc3" => PromotionState::Rc3Review,
            _ => return Err(AuthorityError::NonCanonicalPayload),
        };
        if value.promotion != id
            || value.revision != record.revision
            || !canonical_id(&value.command)
            || record.state != Some(expected)
            || record.commands.contains_key(&value.command)
        {
            return Err(AuthorityError::BindingMismatch);
        }
    }
    Ok(())
}

fn valid_threshold(record: &Record) -> Result<(), AuthorityError> {
    if let Some(outbox) = &record.threshold_outbox {
        let (admission, revision) = outbox.claim();
        if record.threshold_admission != Some(admission)
            || revision != record.revision
            || record.state != Some(PromotionState::SignedEnvelopesVerified)
        {
            return Err(AuthorityError::BindingMismatch);
        }
    }
    if let Some(ack) = &record.threshold_ack {
        let valid = record.threshold_admission == Some(ack.admission)
            && ack.claim_revision + 1 == ack.outcome.revision
            && record
                .commands
                .get(&ack.command)
                .is_some_and(|(fingerprint, outcome)| {
                    *fingerprint == ack.fingerprint && *outcome == ack.outcome
                })
            && record.threshold_outbox.is_none();
        if !valid {
            return Err(AuthorityError::BindingMismatch);
        }
    }
    for (command, (revision, _)) in &record.completed_verify {
        let valid = record.inventory.is_some()
            && record.metadata.is_some()
            && record.report.is_some()
            && record.threshold_admission.is_some()
            && record.commands.get(command).is_some_and(|(_, outcome)| {
                outcome.revision == revision + 1
                    && outcome.state == PromotionState::SignedEnvelopesVerified
            });
        if !valid {
            return Err(AuthorityError::BindingMismatch);
        }
    }
    Ok(())
}

fn valid_publication(wire: &RecordWire, record: &Record) -> Result<(), AuthorityError> {
    let value = &wire.publication;
    let any = [
        value.manifest.is_some(),
        value.authorization.is_some(),
        value.destination.is_some(),
        value.channel.is_some(),
        value.namespace.is_some(),
        value.executor.is_some(),
        value.lane.is_some(),
        value.workflow.is_some(),
        value.valid_from.is_some(),
        value.expires_at.is_some(),
        value.revocation_epoch.is_some(),
    ]
    .into_iter()
    .any(|present| present);
    if !any {
        return Ok(());
    }
    let valid = record.state == Some(PromotionState::PublicationAuthorized)
        && value.destination.as_deref().is_some_and(valid_destination)
        && value
            .channel
            .as_deref()
            .is_some_and(|x| matches!(x, "stable" | "beta" | "internal"))
        && [
            value.namespace.as_deref(),
            value.executor.as_deref(),
            value.lane.as_deref(),
        ]
        .into_iter()
        .all(|value| value.is_some_and(canonical_id))
        && value
            .valid_from
            .zip(value.expires_at)
            .is_some_and(|(from, until)| from < until)
        && value.revocation_epoch.is_some_and(|epoch| epoch > 0);
    valid.then_some(()).ok_or(AuthorityError::BindingMismatch)
}

fn canonical_id(value: &str) -> bool {
    gocode_promotion_contracts::canonical_id(value)
}

fn canonical_time(value: &str) -> bool {
    value.len() == 20
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[13] == b':'
        && value.as_bytes()[16] == b':'
        && value.as_bytes()[19] == b'Z'
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

fn valid_destination(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}
