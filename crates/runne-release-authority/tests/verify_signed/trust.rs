use super::*;

#[test]
fn final_reservation_rejects_expired_or_revoked_evidence_snapshot() {
    let (mut store, id, payloads) = signing_authorized();
    let signed_bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
    store
        .set_rc2_evidence_trust_snapshot(&id, &signing_support::trust_snapshot(2, 1, 2))
        .unwrap();
    assert_eq!(
        store.reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &signed_bundle),
        Err(AuthorityError::BindingMismatch)
    );
    store
        .set_rc2_evidence_trust_snapshot(&id, &signing_support::trust_snapshot(1, 2, 3))
        .unwrap();
    assert_eq!(
        store.reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &signed_bundle),
        Err(AuthorityError::BindingMismatch)
    );
}

#[test]
fn final_commit_rechecks_the_reserved_evidence_snapshot() {
    let (mut store, id, payloads) = signing_authorized();
    let signed_bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &signed_bundle)
        .unwrap();
    let proof =
        admit_prevalidated_signed_bundle(signed_bundle, receipt, &Context::valid()).unwrap();
    store
        .set_rc2_evidence_trust_snapshot(&id, &signing_support::trust_snapshot(2, 1, 2))
        .unwrap();
    assert_eq!(
        store.transact(
            &id,
            4,
            CommandId::fixture("verify"),
            Mutation::VerifySigned {
                proof: Box::new(proof),
            },
        ),
        Err(AuthorityError::BindingMismatch)
    );
}
