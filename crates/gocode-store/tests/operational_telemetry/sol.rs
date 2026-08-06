use super::fixture::Fixture;

#[test]
fn authority_candidate_dispatch_mutations_are_localized() {
    for mutation in [
        "attempt_id = zeroblob(16)",
        "call_id = zeroblob(16)",
        "permit_id = zeroblob(16)",
        "token_reservation_id = zeroblob(16)",
        "cost_reservation_id = zeroblob(16)",
        "fencing_token = 12",
        "provider_idempotency_key = 'mismatch'",
        "prepared_digest = zeroblob(32)",
        "render_digest = zeroblob(32)",
        "profile_digest = zeroblob(32)",
        "state = 99",
    ] {
        let fixture = Fixture::new();
        fixture.issue(20);
        fixture
            .connection()
            .execute_batch(&format!(
                "PRAGMA foreign_keys = OFF;
             PRAGMA ignore_check_constraints = ON;
             UPDATE provider_dispatch_attempts SET {mutation};"
            ))
            .unwrap();

        let telemetry = fixture.read().unwrap();
        assert!(
            telemetry.provider_effect_authorities().is_none(),
            "{mutation}"
        );
        assert!(telemetry.accounting().is_some(), "{mutation}");
        assert!(telemetry.provider_approval_lease().is_some(), "{mutation}");
    }
}

#[test]
fn historical_state_six_dispatch_mismatch_does_not_hide_valid_authority() {
    let fixture = Fixture::new();
    fixture.issue(21);
    fixture.issue(22);
    fixture
        .connection()
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
         PRAGMA ignore_check_constraints = ON;
         UPDATE provider_execution_admissions
         SET generation = 10 WHERE provider_idempotency_key = 'provider-22';
         UPDATE provider_dispatch_attempts
         SET state = 6, permit_id = zeroblob(16)
         WHERE provider_idempotency_key = 'provider-22';",
        )
        .unwrap();

    let telemetry = fixture.read().unwrap();
    assert_eq!(
        telemetry.provider_effect_authorities().unwrap().values().0,
        1
    );
    assert!(telemetry.accounting().is_some());
    assert!(telemetry.provider_approval_lease().is_some());
}

#[test]
fn started_effect_dispatch_mismatch_keeps_authority_available_empty() {
    let fixture = Fixture::new();
    fixture.issue_and_start_effect(23);
    fixture
        .connection()
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
         UPDATE provider_dispatch_attempts SET permit_id = zeroblob(16);",
        )
        .unwrap();

    let telemetry = fixture.read().unwrap();
    assert_eq!(
        telemetry.provider_effect_authorities().unwrap().values(),
        (0, 0, None)
    );
    assert!(telemetry.committed_provider_effects().is_none());
    assert!(telemetry.uncertain_attempts().is_none());
    assert!(telemetry.accounting().is_some());
    assert!(telemetry.provider_approval_lease().is_some());
}
