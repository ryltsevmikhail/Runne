use super::{RecordWire, claim::StageClaimWire};
use crate::{AuthorityError, Digest, PromotionState, store_machine::Record};

pub(super) fn validate(id: &str, wire: &RecordWire, record: &Record) -> Result<(), AuthorityError> {
    let mut commands = std::collections::BTreeSet::new();
    for value in &wire.stage_claims {
        let payload = super::read::d(&value.payload)?.as_bytes();
        let (kind, state, staged) = stage(value.role.as_str(), record)?;
        let claim = record
            .stage_claims
            .get(&value.nonce)
            .ok_or(AuthorityError::BindingMismatch)?;
        let valid = basic(value, id, record, kind, payload, staged)?
            && value.kind == kind_name(kind)
            && claim.admission_fingerprint
                == crate::store_stage_claim::stored_admission_fingerprint(claim)
            && command(value, record, kind, state, claim)?
            && commands.insert(value.command.as_str());
        if !valid {
            return Err(AuthorityError::BindingMismatch);
        }
    }
    record
        .commands
        .iter()
        .filter(|(_, (_, outcome))| completed_stage(outcome.state))
        .all(|(command, _)| commands.contains(command.as_str()))
        .then_some(())
        .ok_or(AuthorityError::BindingMismatch)
}

fn stage(
    role: &str,
    record: &Record,
) -> Result<
    (
        gocode_promotion_contracts::CanonicalPayloadKind,
        PromotionState,
        Option<[u8; 32]>,
    ),
    AuthorityError,
> {
    match role {
        "RC1_QUALIFICATION_AUTHORIZER" => Ok((
            gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision,
            PromotionState::QualifiedUnsigned,
            record.rc1.as_ref().map(|stage| stage.sha256),
        )),
        "RC2_SIGNING_AUTHORIZER" => Ok((
            gocode_promotion_contracts::CanonicalPayloadKind::Rc2Authorization,
            PromotionState::SigningAuthorized,
            record.rc2.as_ref().map(|stage| stage.sha256),
        )),
        "RC3_PUBLICATION_AUTHORIZER" => Ok((
            gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization,
            PromotionState::PublicationAuthorized,
            record.publication_authorization.map(Digest::as_bytes),
        )),
        _ => Err(AuthorityError::NonCanonicalPayload),
    }
}

fn basic(
    value: &StageClaimWire,
    id: &str,
    record: &Record,
    kind: gocode_promotion_contracts::CanonicalPayloadKind,
    payload: [u8; 32],
    staged: Option<[u8; 32]>,
) -> Result<bool, AuthorityError> {
    let reservation = crate::store_command::stage_reservation_fingerprint(
        &crate::PromotionId::try_fixture(id)?,
        value.revision,
        &value.command,
        kind,
    );
    Ok(super::read::d(&value.fingerprint).is_ok_and(|fingerprint| {
        value.promotion == id
            && canonical_id(&value.nonce)
            && canonical_id(&value.command)
            && value.revision < record.revision
            && value.root_epoch > 0
            && value.root_epoch <= record.stage_trust.root_epoch
            && value.role_floor > 0
            && value.role_floor <= record.stage_trust.role_floor
            && value.envelope_epoch > 0
            && value.payload_epoch > 0
            && value.role_floor <= value.envelope_epoch
            && value.payload_epoch == value.envelope_epoch
            && value.payload_valid_from < value.payload_expires_at
            && times(value)
            && staged == Some(payload)
            && fingerprint.as_bytes() == reservation
    }))
}

fn command(
    value: &StageClaimWire,
    record: &Record,
    kind: gocode_promotion_contracts::CanonicalPayloadKind,
    state: PromotionState,
    claim: &crate::store_stage_claim::StoredStageClaim,
) -> Result<bool, AuthorityError> {
    let fingerprint = match kind {
        gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision
        | gocode_promotion_contracts::CanonicalPayloadKind::Rc2Authorization => {
            crate::store_command::stage_command_fingerprint(
                value.revision,
                kind,
                crate::store_stage_claim::stored_command_fingerprint(claim),
            )
        }
        gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization => {
            crate::store_command::publication_stage_command_fingerprint(
                value.revision,
                record
                    .publication_manifest
                    .ok_or(AuthorityError::BindingMismatch)?,
                record
                    .publication_destination
                    .as_deref()
                    .ok_or(AuthorityError::BindingMismatch)?,
                record
                    .publication_channel
                    .as_deref()
                    .ok_or(AuthorityError::BindingMismatch)?,
                crate::store_stage_claim::stored_command_fingerprint(claim),
            )
        }
    };
    Ok(record
        .commands
        .get(&value.command)
        .is_some_and(|(stored, outcome)| {
            *stored == fingerprint
                && outcome.revision == value.revision + 1
                && outcome.state == state
        }))
}

fn times(value: &StageClaimWire) -> bool {
    [
        &value.bootstrap_not_before,
        &value.bootstrap_expires_at,
        &value.envelope_not_before,
        &value.envelope_expires_at,
    ]
    .into_iter()
    .all(|value| canonical_time(value))
        && value.bootstrap_not_before < value.bootstrap_expires_at
        && value.envelope_not_before < value.envelope_expires_at
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

const fn completed_stage(state: PromotionState) -> bool {
    matches!(
        state,
        PromotionState::QualifiedUnsigned
            | PromotionState::SigningAuthorized
            | PromotionState::PublicationAuthorized
    )
}

const fn kind_name(value: gocode_promotion_contracts::CanonicalPayloadKind) -> &'static str {
    match value {
        gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision => "rc1",
        gocode_promotion_contracts::CanonicalPayloadKind::Rc2Authorization => "rc2",
        gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization => "rc3",
    }
}

fn canonical_id(value: &str) -> bool {
    gocode_promotion_contracts::canonical_id(value)
}
