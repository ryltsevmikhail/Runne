use super::{
    AckWire, AuthorityError, BindingWire, CommandWire, CompletedWire, EffectAuthorizationWire,
    EffectSlotWire, EvidenceKeyWire, FileState, PromotionId, PublicationWire, RecordWire,
    ReservationWire, SnapshotWire, StageReservationWire, ThresholdFixtureStoreBinding, facts, h,
    opt, outbox, outcome, stage, stage_claims, state,
};

#[allow(clippy::too_many_lines)] // Canonical scalar projection must be written atomically.
pub fn from_record(
    binding: &ThresholdFixtureStoreBinding,
    id: &PromotionId,
    record: &crate::store_machine::Record,
) -> Result<FileState, AuthorityError> {
    let b = record.binding.ok_or(AuthorityError::BindingMismatch)?;
    Ok(FileState {
        schema_version: "gocode.release.durable-promotion-store/1".into(),
        bootstrap: binding.bootstrap.to_hex(),
        profile: binding.profile.clone(),
        version: binding.version,
        promotion: id.0.clone(),
        record: RecordWire {
            authority_instance: h(record.authority_instance),
            state: state(record.state.ok_or(AuthorityError::InvalidTransition)?).into(),
            revision: record.revision,
            binding: BindingWire {
                subject: h(b.subject()),
                matrix: h(b.matrix()),
                bootstrap: h(b.bootstrap()),
                candidate: h(b.candidate()),
                policy: h(b.policy()),
                release_facts: b.release_facts().map(h),
                sha256: h(b.sha256()),
            },
            admission: facts::admission(record.admission_facts.as_ref()),
            rc1: record.rc1.as_ref().map(stage),
            rc2: record.rc2.as_ref().map(stage),
            rc2_effect: record.rc2_effect_authorization.as_ref().map(|value| {
                let value = value.fixture();
                EffectAuthorizationWire {
                    authority_instance: h(value.authority_instance),
                    promotion: value.promotion,
                    revision: value.revision,
                    authorization: h(value.authorization),
                    namespace: value.namespace,
                    generation: value.generation,
                    valid_from: value.valid_from,
                    expires_at: value.expires_at,
                    revocation_epoch: value.revocation_epoch,
                    workflow: h(value.workflow),
                    signer: value.signer,
                    runner: value.runner,
                    slots: value
                        .slots
                        .into_iter()
                        .map(|(slot, digest, length)| EffectSlotWire {
                            slot,
                            digest: h(digest),
                            length,
                        })
                        .collect(),
                }
            }),
            inventory: opt(record.inventory),
            metadata: opt(record.metadata),
            report: opt(record.report),
            reservation: record.reservation.as_ref().map(|x| ReservationWire {
                authority_instance: h(x.authority_instance),
                promotion: x.promotion.0.clone(),
                revision: x.revision,
                authorization: h(x.authorization),
                command: x.command.clone(),
                fingerprint: h(x.fingerprint.digest()),
                commitment: h(x.commitment),
                evidence_now: x.evidence_trust.now,
                evidence_revocation_epoch: x.evidence_trust.revocation_epoch,
                evidence_generation: x.evidence_trust.generation,
                evidence_registrations_digest: h(x.evidence_trust.registrations_digest),
                evidence_expires_at: x.evidence_expires_at,
            }),
            stage_reservation: record
                .stage_reservation
                .as_ref()
                .map(|x| StageReservationWire {
                    promotion: x.promotion.0.clone(),
                    revision: x.revision,
                    command: x.command.clone(),
                    kind: stage_kind(x.kind).into(),
                    fingerprint: crate::threshold_fixture_wire::hex(&x.fingerprint),
                }),
            stage_claims: stage_claims(record),
            stage_trust_now: record.stage_trust.now,
            stage_trust_utc: record.stage_trust.utc.clone(),
            stage_trust_root_epoch: record.stage_trust.root_epoch,
            stage_trust_role_floor: record.stage_trust.role_floor,
            rc2_evidence_now: record.rc2_evidence_trust.now,
            rc2_evidence_revocation_epoch: record.rc2_evidence_trust.revocation_epoch,
            rc2_evidence_generation: record.rc2_evidence_trust.generation,
            rc2_evidence_keys: record
                .rc2_evidence_trust
                .registrations
                .iter()
                .map(|key| EvidenceKeyWire {
                    principal: key.identity.principal_id.clone(),
                    account: key.identity.account_id.clone(),
                    lane: key.identity.lane_id.clone(),
                    key: key.identity.key_id.clone(),
                    signature_profile: key.identity.signature_profile_id.clone(),
                    public_key: crate::threshold_fixture_wire::hex(&key.public_key),
                })
                .collect(),
            threshold_admission: opt(record.threshold_admission),
            outbox: record.threshold_outbox.as_ref().map(outbox),
            ack: record.threshold_ack.as_ref().map(|x| AckWire {
                admission: h(x.admission),
                claim_revision: x.claim_revision,
                command: x.command.clone(),
                fingerprint: h(x.fingerprint.digest()),
                outcome: outcome(&x.outcome),
            }),
            commands: record
                .commands
                .iter()
                .map(|(command, (fingerprint, value))| CommandWire {
                    command: command.clone(),
                    fingerprint: h(fingerprint.digest()),
                    outcome: outcome(value),
                })
                .collect(),
            completed_verify: record
                .completed_verify
                .iter()
                .map(|(command, (revision, commitment))| CompletedWire {
                    command: command.clone(),
                    revision: *revision,
                    commitment: h(*commitment),
                })
                .collect(),
            previous_snapshot: opt(record.previous_snapshot),
            snapshot: record.snapshot.as_ref().map(|x| SnapshotWire {
                bytes: crate::threshold_fixture_wire::hex(&x.bytes),
                digest: h(x.digest),
                revision: x.revision,
            }),
            publication: PublicationWire {
                manifest: opt(record.publication_manifest),
                authorization: opt(record.publication_authorization),
                destination: record.publication_destination.clone(),
                channel: record.publication_channel.clone(),
                namespace: record.publication_namespace.clone(),
                executor: record.publication_executor.clone(),
                lane: record.publication_lane.clone(),
                workflow: opt(record.publication_workflow),
                valid_from: record.publication_valid_from,
                expires_at: record.publication_expires_at,
                revocation_epoch: record.publication_revocation_epoch,
            },
        },
    })
}

const fn stage_kind(value: gocode_promotion_contracts::CanonicalPayloadKind) -> &'static str {
    match value {
        gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision => "rc1",
        gocode_promotion_contracts::CanonicalPayloadKind::Rc2Authorization => "rc2",
        gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization => "rc3",
    }
}
