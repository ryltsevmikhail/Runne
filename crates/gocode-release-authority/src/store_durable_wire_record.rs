use super::read::{d, dig, into_outcome, into_stage};
use super::{CommandFingerprint, PromotionId, RecordWire};
use crate::{AuthorityError, store_machine};

#[allow(clippy::too_many_lines)] // Canonical durable scalar restoration is one atomic boundary.
pub(super) fn restore_scalars(
    wire: &RecordWire,
    record: &mut store_machine::Record,
) -> Result<(), AuthorityError> {
    record.authority_instance = d(&wire.authority_instance)?;
    record.inventory = dig(wire.inventory.as_ref())?;
    record.metadata = dig(wire.metadata.as_ref())?;
    record.report = dig(wire.report.as_ref())?;
    record.threshold_admission = dig(wire.threshold_admission.as_ref())?;
    record.stage_trust = crate::store_stage_trust::StoredStageTrust {
        now: wire.stage_trust_now,
        utc: wire.stage_trust_utc.clone(),
        root_epoch: wire.stage_trust_root_epoch,
        role_floor: wire.stage_trust_role_floor,
    };
    if wire.rc2_evidence_revocation_epoch == 0 || wire.rc2_evidence_generation == 0 {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    record.rc2_evidence_trust = crate::store_rc2_evidence_trust::StoredRc2EvidenceTrust {
        now: wire.rc2_evidence_now,
        revocation_epoch: wire.rc2_evidence_revocation_epoch,
        generation: wire.rc2_evidence_generation,
        registrations: wire
            .rc2_evidence_keys
            .iter()
            .map(|key| {
                let bytes = super::read::bytes(&key.public_key)?;
                let public_key = bytes
                    .try_into()
                    .map_err(|_| AuthorityError::NonCanonicalPayload)?;
                Ok(crate::FixtureEvidenceKeyRegistration::new(
                    &key.principal,
                    &key.account,
                    &key.lane,
                    &key.key,
                    &key.signature_profile,
                    public_key,
                ))
            })
            .collect::<Result<Vec<_>, AuthorityError>>()?,
    };
    record.admission_facts = wire
        .admission
        .as_ref()
        .map(|value| {
            crate::admission_facts::StoredAdmissionFacts::from_durable(
                record.binding.ok_or(AuthorityError::BindingMismatch)?,
                d(&value.unsigned)?,
                super::read::bytes(&value.manifest)?,
                value.release_facts.clone(),
            )
        })
        .transpose()?;
    record.publication_manifest = dig(wire.publication.manifest.as_ref())?;
    record.publication_authorization = dig(wire.publication.authorization.as_ref())?;
    record
        .publication_destination
        .clone_from(&wire.publication.destination);
    record
        .publication_channel
        .clone_from(&wire.publication.channel);
    record
        .publication_namespace
        .clone_from(&wire.publication.namespace);
    record
        .publication_executor
        .clone_from(&wire.publication.executor);
    record.publication_lane.clone_from(&wire.publication.lane);
    record.publication_workflow = dig(wire.publication.workflow.as_ref())?;
    record.publication_valid_from = wire.publication.valid_from;
    record.publication_expires_at = wire.publication.expires_at;
    record.publication_revocation_epoch = wire.publication.revocation_epoch;
    record.rc1 = wire.rc1.as_ref().map(into_stage).transpose()?;
    record.rc2 = wire.rc2.as_ref().map(into_stage).transpose()?;
    record.rc2_effect_authorization = wire
        .rc2_effect
        .as_ref()
        .map(|value| {
            let slots: Vec<_> = value
                .slots
                .iter()
                .map(|slot| Ok((slot.slot.clone(), d(&slot.digest)?, slot.length)))
                .collect::<Result<_, AuthorityError>>()?;
            crate::rc2_effect_lease::Rc2SigningAuthorizationFixture {
                authority_instance: d(&value.authority_instance)?,
                promotion: value.promotion.clone(),
                revision: value.revision,
                authorization: d(&value.authorization)?,
                namespace: value.namespace.clone(),
                generation: value.generation,
                valid_from: value.valid_from,
                expires_at: value.expires_at,
                revocation_epoch: value.revocation_epoch,
                workflow: d(&value.workflow)?,
                signer: value.signer.clone(),
                runner: value.runner.clone(),
                slots: slots
                    .try_into()
                    .map_err(|_| AuthorityError::NonCanonicalPayload)?,
            }
            .signing_authorized()
            .map_err(|_| AuthorityError::NonCanonicalPayload)
        })
        .transpose()?;
    if (record.rc2.is_some()) != (record.rc2_effect_authorization.is_some()) {
        return Err(AuthorityError::BindingMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Reservation restoration validates one complete durable record.
pub(super) fn restore_reservation(
    wire: &RecordWire,
    record: &mut store_machine::Record,
) -> Result<(), AuthorityError> {
    record.reservation = wire
        .reservation
        .as_ref()
        .map(|value| {
            Ok(store_machine::StoredVerifySignedReservation {
                authority_instance: d(&value.authority_instance)?,
                promotion: PromotionId::try_fixture(&value.promotion)?,
                revision: value.revision,
                authorization: d(&value.authorization)?,
                command: value.command.clone(),
                fingerprint: CommandFingerprint::derived(d(&value.fingerprint)?),
                commitment: d(&value.commitment)?,
                evidence_trust: crate::rc2_evidence_common::EvidenceTrustBinding {
                    now: value.evidence_now,
                    revocation_epoch: value.evidence_revocation_epoch,
                    generation: value.evidence_generation,
                    registrations_digest: d(&value.evidence_registrations_digest)?,
                },
                evidence_expires_at: value.evidence_expires_at,
            })
        })
        .transpose()?;
    record.stage_reservation = wire
        .stage_reservation
        .as_ref()
        .map(|value| {
            let kind = match value.kind.as_str() {
                "rc1" => gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision,
                "rc2" => gocode_promotion_contracts::CanonicalPayloadKind::Rc2Authorization,
                "rc3" => gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization,
                _ => return Err(AuthorityError::NonCanonicalPayload),
            };
            let fingerprint = d(&value.fingerprint)?.as_bytes();
            Ok(
                crate::store_stage_reservation::StoredStageTransitionReservation {
                    promotion: PromotionId::try_fixture(&value.promotion)?,
                    revision: value.revision,
                    command: value.command.clone(),
                    kind,
                    fingerprint,
                },
            )
        })
        .transpose()?;
    for value in &wire.stage_claims {
        let claim = crate::store_stage_claim::StoredStageClaim {
            nonce: value.nonce.clone(),
            envelope: d(&value.envelope)?.as_bytes(),
            payload: d(&value.payload)?.as_bytes(),
            bootstrap: d(&value.bootstrap)?.as_bytes(),
            role: value.role.clone(),
            promotion: value.promotion.clone(),
            revision: value.revision,
            command: value.command.clone(),
            kind: match value.kind.as_str() {
                "rc1" => gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision,
                "rc2" => gocode_promotion_contracts::CanonicalPayloadKind::Rc2Authorization,
                "rc3" => gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization,
                _ => return Err(AuthorityError::NonCanonicalPayload),
            },
            fingerprint: d(&value.fingerprint)?.as_bytes(),
            admission_fingerprint: d(&value.admission_fingerprint)?.as_bytes(),
            bootstrap_not_before: value.bootstrap_not_before.clone(),
            bootstrap_expires_at: value.bootstrap_expires_at.clone(),
            root_epoch: value.root_epoch,
            envelope_not_before: value.envelope_not_before.clone(),
            envelope_expires_at: value.envelope_expires_at.clone(),
            envelope_epoch: value.envelope_epoch,
            payload_valid_from: value.payload_valid_from,
            payload_expires_at: value.payload_expires_at,
            payload_epoch: value.payload_epoch,
            role_floor: value.role_floor,
        };
        if claim.nonce.is_empty()
            || record
                .stage_claims
                .insert(claim.nonce.clone(), claim)
                .is_some()
        {
            return Err(AuthorityError::NonCanonicalPayload);
        }
    }
    record.threshold_outbox = wire
        .outbox
        .as_ref()
        .map(|value| {
            Ok(match value.state.as_str() {
                "pending" => crate::store_stage_trust::ThresholdAckDelivery::Pending {
                    admission: d(&value.admission)?,
                    revision: value.revision,
                },
                "delivering" => crate::store_stage_trust::ThresholdAckDelivery::Delivering {
                    admission: d(&value.admission)?,
                    revision: value.revision,
                    command: value
                        .command
                        .clone()
                        .ok_or(AuthorityError::NonCanonicalPayload)?,
                },
                _ => return Err(AuthorityError::NonCanonicalPayload),
            })
        })
        .transpose()?;
    Ok(())
}

pub(super) fn restore_commands(
    wire: &RecordWire,
    record: &mut store_machine::Record,
) -> Result<(), AuthorityError> {
    for value in &wire.commands {
        if record
            .commands
            .insert(
                value.command.clone(),
                (
                    CommandFingerprint::derived(d(&value.fingerprint)?),
                    into_outcome(&value.outcome)?,
                ),
            )
            .is_some()
        {
            return Err(AuthorityError::NonCanonicalPayload);
        }
    }
    for value in &wire.completed_verify {
        if record
            .completed_verify
            .insert(
                value.command.clone(),
                (value.revision, d(&value.commitment)?),
            )
            .is_some()
        {
            return Err(AuthorityError::NonCanonicalPayload);
        }
    }
    Ok(())
}

pub(super) fn restore_snapshot(
    wire: &RecordWire,
    record: &mut store_machine::Record,
) -> Result<(), AuthorityError> {
    record.previous_snapshot = dig(wire.previous_snapshot.as_ref())?;
    record.snapshot = wire
        .snapshot
        .as_ref()
        .map(super::snapshot::decode)
        .transpose()?;
    record.threshold_ack = wire
        .ack
        .as_ref()
        .map(|value| {
            Ok(crate::store_stage_trust::ThresholdAckTombstone {
                admission: d(&value.admission)?,
                claim_revision: value.claim_revision,
                command: value.command.clone(),
                fingerprint: CommandFingerprint::derived(d(&value.fingerprint)?),
                outcome: into_outcome(&value.outcome)?,
            })
        })
        .transpose()?;
    Ok(())
}
