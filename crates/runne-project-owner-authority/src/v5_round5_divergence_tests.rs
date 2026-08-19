use crate::v5_round5_test_store::{AllowlistContext, EvidenceContext, StageContext, StatefulStore};

fn replay_states(
    expected: &crate::AuthorityStateSnapshot,
) -> (crate::AuthorityStateSnapshot, crate::AuthorityStateSnapshot) {
    let current = expected.clone();
    let mut newly = current.clone();
    newly.durable_generation += 1;
    (current, newly)
}

#[test]
fn stage_store_rejects_full_immutable_request_divergence() {
    let context = StageContext(StatefulStore::new(crate::v5_envelope_test_support::state(
        5,
    )));
    crate::admit_prevalidated_stage_envelope_v2(crate::v5_round5_fixtures::stage(), &context)
        .unwrap();
    let stored = context.0.stored.borrow().as_ref().unwrap().clone();
    let mutations: [fn(&mut crate::StageEnvelopeAdmissionRequest); 10] = [
        |r| r.promotion.receipt_sha256[0] ^= 1,
        |r| r.command.nonce.push('x'),
        |r| r.command.envelope_sha256[0] ^= 1,
        |r| r.scope.envelope_sha256[0] ^= 1,
        |r| r.scope.payload_sha256[0] ^= 1,
        |r| r.scope.payload_schema_sha256[0] ^= 1,
        |r| r.revision.receipt_generation += 1,
        |r| r.revision.payload_schema_sha256[0] ^= 1,
        |r| r.reservation.0[0] ^= 1,
        |r| r.outcome.0[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = stored.clone();
        (changed.expected, changed.newly_admitted_state) = replay_states(&context.0.state.borrow());
        mutate(&mut changed);
        assert_eq!(
            context.0.admit(&changed),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
    }
}

#[test]
fn evidence_store_rejects_full_immutable_request_divergence() {
    let context = EvidenceContext(StatefulStore::new(crate::v5_envelope_test_support::state(
        5,
    )));
    crate::admit_prevalidated_evidence_envelope_v2(crate::v5_round5_fixtures::evidence(), &context)
        .unwrap();
    let stored = context.0.stored.borrow().as_ref().unwrap().clone();
    let mutations: [fn(&mut crate::EvidenceEnvelopeAdmissionRequest); 10] = [
        |r| r.promotion.receipt_sha256[0] ^= 1,
        |r| r.command.nonce.push('x'),
        |r| r.command.payload_sha256[0] ^= 1,
        |r| r.scope.envelope_sha256[0] ^= 1,
        |r| r.scope.payload_sha256[0] ^= 1,
        |r| r.scope.payload_schema_sha256[0] ^= 1,
        |r| r.revision.allowlist_generation += 1,
        |r| r.revision.payload_schema_sha256[0] ^= 1,
        |r| r.reservation.0[0] ^= 1,
        |r| r.outcome.0[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = stored.clone();
        (changed.expected, changed.newly_admitted_state) = replay_states(&context.0.state.borrow());
        mutate(&mut changed);
        assert_eq!(
            context.0.admit(&changed),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
    }
}

#[test]
fn allowlist_store_rejects_full_immutable_request_divergence() {
    let context = AllowlistContext(StatefulStore::new(crate::v5_envelope_test_support::state(
        5,
    )));
    crate::admit_prevalidated_destination_allowlist_v1(
        crate::v5_round5_fixtures::allowlist(),
        &context,
    )
    .unwrap();
    let stored = context.0.stored.borrow().as_ref().unwrap().clone();
    let mutations: [fn(&mut crate::DestinationAllowlistAdmissionRequest); 10] = [
        |r| r.promotion.receipt_sha256[0] ^= 1,
        |r| r.command.nonce.push('x'),
        |r| r.command.envelope_sha256[0] ^= 1,
        |r| r.scope.allowlist_sha256[0] ^= 1,
        |r| r.scope.unsigned_sha256[0] ^= 1,
        |r| r.revision.payload_schema_sha256[0] ^= 1,
        |r| r.revision.allowlist_generation += 1,
        |r| r.scope.policy_id.push('x'),
        |r| r.reservation.0[0] ^= 1,
        |r| r.outcome.0[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = stored.clone();
        (changed.expected, changed.newly_admitted_state) = replay_states(&context.0.state.borrow());
        mutate(&mut changed);
        assert_eq!(
            context.0.admit(&changed),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
    }
}
