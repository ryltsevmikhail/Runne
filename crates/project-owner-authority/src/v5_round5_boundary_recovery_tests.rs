use crate::v5_round5_test_store::{AllowlistContext, EvidenceContext, StageContext, StatefulStore};

fn stage_context() -> StageContext {
    StageContext(StatefulStore::new(crate::v5_envelope_test_support::state(
        5,
    )))
}
fn evidence_context() -> EvidenceContext {
    EvidenceContext(StatefulStore::new(crate::v5_envelope_test_support::state(
        5,
    )))
}
fn allowlist_context() -> AllowlistContext {
    AllowlistContext(StatefulStore::new(crate::v5_envelope_test_support::state(
        5,
    )))
}

#[test]
fn all_boundaries_recover_response_loss_and_identical_post_expiry_replay() {
    let stage = stage_context();
    crate::admit_prevalidated_stage_envelope_v2(crate::v5_round5_fixtures::stage(), &stage)
        .unwrap();
    stage.0.after_expiry.set(true);
    crate::admit_prevalidated_stage_envelope_v2(crate::v5_round5_fixtures::stage(), &stage)
        .unwrap();

    let evidence = evidence_context();
    crate::admit_prevalidated_evidence_envelope_v2(
        crate::v5_round5_fixtures::evidence(),
        &evidence,
    )
    .unwrap();
    evidence.0.after_expiry.set(true);
    crate::admit_prevalidated_evidence_envelope_v2(
        crate::v5_round5_fixtures::evidence(),
        &evidence,
    )
    .unwrap();

    let allowlist = allowlist_context();
    crate::admit_prevalidated_destination_allowlist_v1(
        crate::v5_round5_fixtures::allowlist(),
        &allowlist,
    )
    .unwrap();
    allowlist.0.after_expiry.set(true);
    crate::admit_prevalidated_destination_allowlist_v1(
        crate::v5_round5_fixtures::allowlist(),
        &allowlist,
    )
    .unwrap();

    for (calls, recoveries) in [
        (stage.0.calls.get(), stage.0.recoveries.get()),
        (evidence.0.calls.get(), evidence.0.recoveries.get()),
        (allowlist.0.calls.get(), allowlist.0.recoveries.get()),
    ] {
        assert_eq!((calls, recoveries), (2, 1));
    }
    for state in [
        stage.0.state.borrow().clone(),
        evidence.0.state.borrow().clone(),
        allowlist.0.state.borrow().clone(),
    ] {
        assert_eq!(state.durable_generation, 2);
        assert_eq!(state.active_trust_generation, 4);
        assert_eq!(state.active_receipt_generation, 5);
        assert_eq!(state.active_allowlist_generation, 1);
    }
}

#[test]
fn all_boundaries_reject_first_admission_after_expiry() {
    let stage = stage_context();
    stage.0.after_expiry.set(true);
    assert_eq!(
        crate::admit_prevalidated_stage_envelope_v2(crate::v5_round5_fixtures::stage(), &stage),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
    let evidence = evidence_context();
    evidence.0.after_expiry.set(true);
    assert_eq!(
        crate::admit_prevalidated_evidence_envelope_v2(
            crate::v5_round5_fixtures::evidence(),
            &evidence
        ),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
    let allowlist = allowlist_context();
    allowlist.0.after_expiry.set(true);
    assert_eq!(
        crate::admit_prevalidated_destination_allowlist_v1(
            crate::v5_round5_fixtures::allowlist(),
            &allowlist
        ),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
}

#[test]
fn all_boundaries_reject_stale_concurrent_cas_without_persisting() {
    let stage = stage_context();
    stage.0.race.set(true);
    assert_eq!(
        crate::admit_prevalidated_stage_envelope_v2(crate::v5_round5_fixtures::stage(), &stage),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
    assert!(stage.0.stored.borrow().is_none());

    let evidence = evidence_context();
    evidence.0.race.set(true);
    assert_eq!(
        crate::admit_prevalidated_evidence_envelope_v2(
            crate::v5_round5_fixtures::evidence(),
            &evidence
        ),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
    assert!(evidence.0.stored.borrow().is_none());

    let allowlist = allowlist_context();
    allowlist.0.race.set(true);
    assert_eq!(
        crate::admit_prevalidated_destination_allowlist_v1(
            crate::v5_round5_fixtures::allowlist(),
            &allowlist
        ),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
    assert!(allowlist.0.stored.borrow().is_none());
}

#[test]
fn all_boundaries_reject_result_state_variant_and_persisted_lies() {
    for flag in 0..3 {
        let stage = stage_context();
        set_lie(&stage.0, flag);
        assert_eq!(
            crate::admit_prevalidated_stage_envelope_v2(crate::v5_round5_fixtures::stage(), &stage),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
        let evidence = evidence_context();
        set_lie(&evidence.0, flag);
        assert_eq!(
            crate::admit_prevalidated_evidence_envelope_v2(
                crate::v5_round5_fixtures::evidence(),
                &evidence
            ),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
        let allowlist = allowlist_context();
        set_lie(&allowlist.0, flag);
        assert_eq!(
            crate::admit_prevalidated_destination_allowlist_v1(
                crate::v5_round5_fixtures::allowlist(),
                &allowlist
            ),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
    }
}

macro_rules! assert_existing_same_lies_read_only {
    ($context:expr, $admit:expr, $fixture:expr) => {
        for flag in 0..3 {
            let context = $context;
            ($admit)(($fixture)(), &context).unwrap();
            let state = context.0.state.borrow().clone();
            let stored = context.0.stored.borrow().clone();
            set_lie(&context.0, flag);
            assert_eq!(
                ($admit)(($fixture)(), &context),
                Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
            );
            assert_eq!(*context.0.state.borrow(), state);
            assert_eq!(*context.0.stored.borrow(), stored);
        }
    };
}

#[test]
fn existing_same_lies_leave_all_boundary_stores_unchanged() {
    assert_existing_same_lies_read_only!(
        stage_context(),
        crate::admit_prevalidated_stage_envelope_v2,
        crate::v5_round5_fixtures::stage
    );
    assert_existing_same_lies_read_only!(
        evidence_context(),
        crate::admit_prevalidated_evidence_envelope_v2,
        crate::v5_round5_fixtures::evidence
    );
    assert_existing_same_lies_read_only!(
        allowlist_context(),
        crate::admit_prevalidated_destination_allowlist_v1,
        crate::v5_round5_fixtures::allowlist
    );
}

fn set_lie<R>(store: &StatefulStore<R>, flag: u8) {
    match flag {
        0 => store.wrong_state.set(true),
        1 => store.wrong_persisted.set(true),
        2 => store.wrong_variant.set(true),
        _ => unreachable!(),
    }
}
