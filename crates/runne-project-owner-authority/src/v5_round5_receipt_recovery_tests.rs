use crate::v5_round5_test_store::{ReceiptContext, StatefulStore};

fn context() -> ReceiptContext {
    ReceiptContext(StatefulStore::new(crate::v5_envelope_test_support::state(
        4,
    )))
}

fn admit(
    context: &ReceiptContext,
) -> Result<crate::VerifiedPromotionBootstrapV5, crate::AuthorityError> {
    crate::admit_prevalidated_promotion_authority_receipt_v5(
        crate::v5_round5_fixtures::receipt(),
        context,
    )
}

#[test]
fn response_loss_and_post_expiry_retry_recover_receipt_from_generation_five() {
    let context = context();
    let _lost_response = admit(&context).unwrap();
    context.0.after_expiry.set(true);
    admit(&context).expect("identical response-loss retry must recover after expiry");
    admit(&context).expect("later identical post-expiry replay must remain recoverable");
    assert_eq!(context.0.calls.get(), 3);
    assert_eq!(context.0.recoveries.get(), 2);
    assert_eq!(context.0.state.borrow().active_receipt_generation, 5);
}

#[test]
fn a_first_receipt_admission_after_expiry_is_not_treated_as_recovery() {
    let context = context();
    context.0.after_expiry.set(true);
    assert_eq!(
        admit(&context),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
    assert!(context.0.stored.borrow().is_none());
}

#[test]
fn receipt_rejects_result_state_and_persisted_identity_lies() {
    for configure in [
        |store: &StatefulStore<crate::ReceiptV5AdmissionRequest>| store.wrong_state.set(true),
        |store: &StatefulStore<crate::ReceiptV5AdmissionRequest>| store.wrong_persisted.set(true),
    ] {
        let context = context();
        configure(&context.0);
        assert_eq!(
            admit(&context),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
    }

    for configure in [
        |store: &StatefulStore<crate::ReceiptV5AdmissionRequest>| store.wrong_state.set(true),
        |store: &StatefulStore<crate::ReceiptV5AdmissionRequest>| store.wrong_persisted.set(true),
    ] {
        let context = context();
        admit(&context).unwrap();
        let state = context.0.state.borrow().clone();
        let stored = context.0.stored.borrow().clone();
        configure(&context.0);
        assert_eq!(
            admit(&context),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
        assert_eq!(*context.0.state.borrow(), state);
        assert_eq!(*context.0.stored.borrow(), stored);
    }
}

#[test]
fn receipt_store_rejects_every_immutable_replay_divergence() {
    let context = context();
    admit(&context).unwrap();
    let stored = context.0.stored.borrow().as_ref().unwrap().clone();
    let mutations: [fn(&mut crate::ReceiptV5RecoveryRequest); 8] = [
        |r| r.expected.durable_generation += 1,
        |r| r.scope.receipt_sha256[0] ^= 1,
        |r| r.validity.expires_at.push('x'),
        |r| r.promotion.receipt_sha256[0] ^= 1,
        |r| r.revision.trust_generation += 1,
        |r| r.command.nonce.push('x'),
        |r| r.reservation.0[0] ^= 1,
        |r| r.outcome.0[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = recovery_request(&stored, context.0.state.borrow().clone());
        let state = context.0.state.borrow().clone();
        let stored_before = context.0.stored.borrow().clone();
        mutate(&mut changed);
        assert_eq!(
            crate::ReceiptV5VerificationContext::recover_receipt_v5(&context, &changed),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
        assert_eq!(*context.0.state.borrow(), state);
        assert_eq!(*context.0.stored.borrow(), stored_before);
    }
}

fn recovery_request(
    stored: &crate::ReceiptV5AdmissionRequest,
    expected: crate::AuthorityStateSnapshot,
) -> crate::ReceiptV5RecoveryRequest {
    crate::ReceiptV5RecoveryRequest {
        expected,
        scope: stored.scope.clone(),
        validity: stored.validity.clone(),
        promotion: stored.promotion.clone(),
        revision: stored.revision.clone(),
        command: stored.command.clone(),
        reservation: stored.reservation.clone(),
        outcome: stored.outcome.clone(),
    }
}

#[test]
fn stale_receipt_cas_loses_without_overwriting_persisted_state() {
    let context = context();
    context.0.race.set(true);
    assert_eq!(
        admit(&context),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
    assert!(context.0.stored.borrow().is_none());
}

#[test]
fn generation_five_without_a_stored_receipt_cannot_enter_new_admission() {
    let initial = crate::v5_envelope_test_support::state(5);
    let context = ReceiptContext(StatefulStore::new(initial.clone()));
    assert_eq!(
        admit(&context),
        Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
    );
    assert_eq!(*context.0.state.borrow(), initial);
    assert!(context.0.stored.borrow().is_none());
    assert_eq!(context.0.new_receipt_calls.get(), 0);
    assert_eq!(context.0.receipt_recovery_lookups.get(), 1);
}
