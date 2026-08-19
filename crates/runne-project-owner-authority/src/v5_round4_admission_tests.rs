use std::cell::{Cell, RefCell};

use sha2::{Digest, Sha256};

use crate::v5_envelope_test_support::*;

struct CasContext {
    state: RefCell<crate::AuthorityStateSnapshot>,
    stored: RefCell<Option<crate::StageEnvelopeAdmissionRequest>>,
    cas_calls: Cell<u8>,
    race: Cell<bool>,
    wrong_result: Cell<bool>,
    recoveries: Cell<u8>,
}
impl CasContext {
    fn new() -> Self {
        Self {
            state: RefCell::new(state(5)),
            stored: RefCell::new(None),
            cas_calls: Cell::new(0),
            race: Cell::new(false),
            wrong_result: Cell::new(false),
            recoveries: Cell::new(0),
        }
    }
}
impl crate::V5EnvelopeVerificationContext for CasContext {
    fn read_authority_state(&self) -> Result<crate::AuthorityStateSnapshot, crate::AuthorityError> {
        Ok(self.state.borrow().clone())
    }
    fn admit_or_recover_stage(
        &self,
        request: &crate::StageEnvelopeAdmissionRequest,
    ) -> Result<crate::DurableAdmission, crate::AuthorityError> {
        self.cas_calls.set(self.cas_calls.get() + 1);
        if self.race.replace(false) {
            self.state.borrow_mut().durable_generation += 1;
            return Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict);
        }
        let persisted = if self.wrong_result.get() {
            crate::PersistedAdmission {
                reservation: crate::ReservationIdentity([0; 32]),
                outcome: crate::OutcomeIdentity([0; 32]),
            }
        } else {
            crate::PersistedAdmission {
                reservation: request.reservation.clone(),
                outcome: request.outcome.clone(),
            }
        };
        let mut stored = self.stored.borrow_mut();
        if let Some(existing) = stored.as_ref() {
            let mut replay = request.clone();
            replay.expected = existing.expected.clone();
            replay.newly_admitted_state = existing.newly_admitted_state.clone();
            if &replay != existing {
                return Err(crate::AuthorityError::ReplayedStageEnvelope);
            }
            self.recoveries.set(self.recoveries.get() + 1);
            return Ok(crate::DurableAdmission::ExistingSame {
                persisted,
                state: request.expected.clone(),
            });
        }
        *stored = Some(request.clone());
        self.state.borrow_mut().durable_generation += 1;
        Ok(crate::DurableAdmission::NewlyAdmitted {
            persisted,
            state: request.newly_admitted_state.clone(),
        })
    }
    fn admit_or_recover_evidence(
        &self,
        request: &crate::EvidenceEnvelopeAdmissionRequest,
    ) -> Result<crate::DurableAdmission, crate::AuthorityError> {
        Ok(crate::DurableAdmission::NewlyAdmitted {
            persisted: crate::PersistedAdmission {
                reservation: request.reservation.clone(),
                outcome: request.outcome.clone(),
            },
            state: request.newly_admitted_state.clone(),
        })
    }
}

fn prevalidated_stage(
    chain: &Chain,
    payload_byte: Option<u8>,
) -> crate::PrevalidatedStageEnvelopeV2 {
    let (mut stage, key) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    if let Some(byte) = payload_byte {
        stage.payload["candidate_sha256"] =
            serde_json::Value::String(format!("{byte:02x}").repeat(32));
        let payload = crate::canonical_stage_payload(&stage.payload).unwrap();
        stage.payload_sha256 = Sha256::digest(payload).into();
    }
    let bytes = signed_stage_v2(&stage, &key);
    crate::prevalidate_stage_envelope_v2(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.receipt5,
    )
    .unwrap()
}

#[test]
fn authenticated_snapshot_rejects_independent_root_generation_and_floor_drifts_before_cas() {
    let chain = chain();
    let mut states = Vec::new();
    let base = state(5);
    macro_rules! drift {
        ($field:expr) => {{
            let mut changed = base.clone();
            $field(&mut changed);
            states.push(changed);
        }};
    }
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.active_trust_generation += 1);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.active_receipt_generation = 4);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.active_allowlist_generation += 1);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.principal_id.push('x'));
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.controlling_account_id.push('x'));
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.lane_id.push('x'));
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.key_id.push('x'));
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.signature_profile_id.push('x'));
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.public_key[0] ^= 1);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.key_epoch += 1);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root_revocation_floor += 1);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.role_scope_floors[0].revocation_epoch += 1);
    for changed in states {
        let context = CasContext::new();
        *context.state.borrow_mut() = changed;
        assert_eq!(
            crate::admit_prevalidated_stage_envelope_v2(prevalidated_stage(&chain, None), &context),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
        assert_eq!(context.cas_calls.get(), 0);
    }
}

#[test]
fn exact_replay_recovers_but_divergence_race_and_wrong_persisted_result_fail_closed() {
    let chain = chain();
    let context = CasContext::new();
    crate::admit_prevalidated_stage_envelope_v2(prevalidated_stage(&chain, None), &context)
        .unwrap();
    crate::admit_prevalidated_stage_envelope_v2(prevalidated_stage(&chain, None), &context)
        .unwrap();
    assert_eq!(
        context.recoveries.get(),
        1,
        "identical replay may recover after expiry"
    );
    let stored = context.stored.borrow().as_ref().unwrap().clone();
    let mutations: [fn(&mut crate::StageEnvelopeAdmissionRequest); 6] = [
        |request| request.scope.envelope_sha256[0] ^= 1,
        |request| request.scope.payload_sha256[0] ^= 1,
        |request| request.revision.trust_generation += 1,
        |request| request.command.envelope_sha256[0] ^= 1,
        |request| request.reservation.0[0] ^= 1,
        |request| request.outcome.0[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = stored.clone();
        mutate(&mut changed);
        assert_eq!(
            crate::V5EnvelopeVerificationContext::admit_or_recover_stage(&context, &changed),
            Err(crate::AuthorityError::ReplayedStageEnvelope)
        );
    }
    assert_eq!(
        crate::admit_prevalidated_stage_envelope_v2(prevalidated_stage(&chain, Some(7)), &context),
        Err(crate::AuthorityError::ReplayedStageEnvelope)
    );

    let racing = CasContext::new();
    racing.race.set(true);
    assert_eq!(
        crate::admit_prevalidated_stage_envelope_v2(prevalidated_stage(&chain, None), &racing),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );

    let wrong = CasContext::new();
    wrong.wrong_result.set(true);
    assert_eq!(
        crate::admit_prevalidated_stage_envelope_v2(prevalidated_stage(&chain, None), &wrong),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
}

#[test]
fn stale_allowlist_generation_is_rejected_before_allowlist_cas() {
    struct Context(Cell<u8>);
    impl crate::DestinationAllowlistVerificationContext for Context {
        fn read_authority_state(
            &self,
        ) -> Result<crate::AuthorityStateSnapshot, crate::AuthorityError> {
            let mut state = state(5);
            state.active_allowlist_generation += 1;
            Ok(state)
        }
        fn admit_or_recover_allowlist(
            &self,
            _: &crate::DestinationAllowlistAdmissionRequest,
        ) -> Result<crate::DurableAdmission, crate::AuthorityError> {
            self.0.set(self.0.get() + 1);
            unreachable!()
        }
    }
    let chain = chain();
    let allowlist = allowlist(&chain.trust);
    let unsigned = crate::canonical_unsigned_allowlist_v1(&allowlist).unwrap();
    let receipt5 = allowlist_receipt5(&chain.root, &chain.trust, Sha256::digest(&unsigned).into());
    let bytes = signed_allowlist_v1(&allowlist, &chain.root);
    let prevalidated = crate::prevalidate_destination_allowlist_v1(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.trust,
        &receipt5,
    )
    .unwrap();
    let context = Context(Cell::new(0));
    assert_eq!(
        crate::admit_prevalidated_destination_allowlist_v1(prevalidated, &context),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
    assert_eq!(context.0.get(), 0);
}

#[test]
fn stale_receipt_generation_is_rejected_before_receipt_cas() {
    use crate::receipt_v5_wire_tests::support;
    use ed25519_dalek::SigningKey;

    struct Context(Cell<u8>);
    impl crate::ReceiptV5VerificationContext for Context {
        fn authority_store_profile(&self) -> Result<&str, crate::AuthorityError> {
            Ok("store")
        }
        fn read_authority_state(
            &self,
        ) -> Result<crate::AuthorityStateSnapshot, crate::AuthorityError> {
            Ok(state(6))
        }
        fn admit_receipt_v5(
            &self,
            _: &crate::ReceiptV5AdmissionRequest,
        ) -> Result<crate::NewlyAdmittedReceiptV5, crate::AuthorityError> {
            self.0.set(self.0.get() + 1);
            unreachable!()
        }
        fn recover_receipt_v5(
            &self,
            _: &crate::ReceiptV5RecoveryRequest,
        ) -> Result<crate::ExistingSameReceiptV5, crate::AuthorityError> {
            self.0.set(self.0.get() + 1);
            unreachable!()
        }
    }
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = support::trust(&root, [1; 32]);
    let predecessor =
        support::predecessor(&support::subject(), crate::trust_canonical::hex(&[1; 32]));
    let value = support::receipt(&trust);
    let bytes = support::signed_bytes(&root, &value);
    let prevalidated = crate::prevalidate_promotion_authority_receipt_v5(
        &bytes,
        Sha256::digest(&bytes).into(),
        &trust,
        &predecessor,
        &support::expected(&value),
    )
    .unwrap();
    let context = Context(Cell::new(0));
    assert_eq!(
        crate::admit_prevalidated_promotion_authority_receipt_v5(prevalidated, &context),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
    assert_eq!(context.0.get(), 0);
}
