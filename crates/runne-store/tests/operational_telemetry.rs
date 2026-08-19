#[path = "operational_telemetry/fixture.rs"]
mod fixture;
#[path = "operational_telemetry/reviewer.rs"]
mod reviewer;
#[path = "operational_telemetry/sol.rs"]
mod sol;
#[path = "operational_telemetry/task12_security.rs"]
mod task12_security;

use fixture::Fixture;

#[test]
fn reads_singleton_accounting_and_empty_aggregates() {
    let fixture = Fixture::new();
    let telemetry = fixture.read().unwrap();

    assert_eq!(
        telemetry.accounting().unwrap().token_budget(),
        (10_000, 0, 0, 10_000)
    );
    assert_eq!(
        telemetry.accounting().unwrap().cost_budget_micro_usd(),
        (1_000_000, 0, 0, 1_000_000)
    );
    assert_eq!(
        telemetry.provider_effect_authorities().unwrap().values(),
        (0, 0, None)
    );
    assert_eq!(
        telemetry.committed_provider_effects().unwrap().values(),
        (0, 0, None)
    );
    assert_eq!(telemetry.uncertain_attempts(), Some(0));
}

#[test]
fn reads_positive_singleton_accounting_without_recomputing_reservations() {
    let fixture = Fixture::new();
    fixture.issue(6);
    let expected = fixture.read().unwrap().accounting().unwrap();
    assert_eq!(expected.token_budget(), (10_000, 1_536, 0, 8_464));
    assert_eq!(
        expected.cost_budget_micro_usd(),
        (1_000_000, 50_000, 0, 950_000)
    );

    fixture
        .connection()
        .execute("UPDATE provider_budget_reservations SET amount = 1", [])
        .unwrap();
    let actual = fixture.read().unwrap().accounting().unwrap();
    assert_eq!(actual.token_budget(), expected.token_budget());
    assert_eq!(
        actual.cost_budget_micro_usd(),
        expected.cost_budget_micro_usd()
    );
}

#[test]
fn counts_authority_approval_and_committed_effect_expiry_at_boundary() {
    let fixture = Fixture::new();
    fixture.issue(1);
    fixture.issue_and_start_effect(2);
    let connection = fixture.connection();
    connection.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         UPDATE provider_execution_admissions SET expires_at = 1000000, approval_expires_at = 1000000;
         UPDATE provider_effect_authorities SET expires_at = 1000000;
         UPDATE provider_runtime_authority_state SET approval_expires_at = 1000000;
         UPDATE provider_effect_starts SET effect_started_at = 999880, effect_expires_at = 1000000;",
    ).unwrap();

    let telemetry = fixture.read().unwrap();
    assert_eq!(
        telemetry.provider_effect_authorities().unwrap().values(),
        (1, 1, None)
    );
    assert_eq!(
        telemetry.provider_approval_lease().unwrap().values(),
        (1, 1, None)
    );
    assert_eq!(
        telemetry.committed_provider_effects().unwrap().values(),
        (1, 1, None)
    );
}

#[test]
fn historical_uncertain_and_effect_state_six_are_counted_without_current_fence() {
    let fixture = Fixture::new();
    fixture.issue_and_start_effect(3);
    let connection = fixture.connection();
    connection
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON;
         UPDATE provider_execution_admissions SET generation = 10, fencing_token = 12;
         UPDATE provider_dispatch_attempts SET fencing_token = 12, state = 6;",
        )
        .unwrap();

    let result = fixture.read().unwrap();
    assert_eq!(result.uncertain_attempts(), Some(1));
    assert_eq!(result.committed_provider_effects().unwrap().values().0, 1);
}

#[test]
fn current_uncertain_attempt_is_counted() {
    let fixture = Fixture::new();
    fixture.issue(7);
    fixture
        .connection()
        .execute("UPDATE provider_dispatch_attempts SET state = 6", [])
        .unwrap();

    assert_eq!(fixture.read().unwrap().uncertain_attempts(), Some(1));
}

#[test]
fn current_fence_excludes_effect_states_one_three_and_four() {
    for state in [1, 3, 4] {
        let fixture = Fixture::new();
        fixture.issue_and_start_effect(state as u8);
        let connection = fixture.connection();
        connection
            .execute_batch(&format!(
                "PRAGMA ignore_check_constraints = ON;
             UPDATE provider_execution_admissions SET fencing_token = 12;
             UPDATE provider_dispatch_attempts SET fencing_token = 12, state = {state};"
            ))
            .unwrap();

        assert_eq!(
            fixture
                .read()
                .unwrap()
                .committed_provider_effects()
                .unwrap()
                .values()
                .0,
            0
        );
    }
}

#[test]
fn orphaned_candidate_makes_affected_data_unavailable() {
    let fixture = Fixture::new();
    fixture.issue_and_start_effect(4);
    let connection = fixture.connection();
    connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
         DELETE FROM provider_execution_admissions;
         PRAGMA foreign_keys = ON;",
        )
        .unwrap();

    let telemetry = fixture.read().unwrap();
    assert!(telemetry.accounting().is_some());
    assert!(telemetry.provider_approval_lease().is_some());
    assert!(telemetry.provider_effect_authorities().is_none());
    assert!(telemetry.committed_provider_effects().is_none());
    assert!(telemetry.uncertain_attempts().is_none());
}

#[test]
fn malformed_authority_boolean_makes_only_authority_unavailable() {
    let fixture = Fixture::new();
    fixture.issue(8);
    fixture
        .connection()
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE provider_effect_authorities SET consumed = 2;",
        )
        .unwrap();

    let telemetry = fixture.read().unwrap();
    assert!(telemetry.provider_effect_authorities().is_none());
    assert!(telemetry.accounting().is_some());
    assert!(telemetry.provider_approval_lease().is_some());
    assert!(telemetry.committed_provider_effects().is_some());
    assert!(telemetry.uncertain_attempts().is_some());
}

#[test]
fn corrupt_state_currency_or_accounting_conversion_is_localized() {
    for (mutation, accounting, effects, uncertain) in [
        (
            "UPDATE provider_dispatch_attempts SET state = 99",
            false,
            true,
            true,
        ),
        (
            "UPDATE provider_execution_admissions SET currency = 'EUR'",
            true,
            false,
            false,
        ),
        (
            "UPDATE provider_runtime_authority_state SET token_budget_limit = -1",
            true,
            false,
            false,
        ),
        (
            "UPDATE provider_runtime_authority_state SET token_budget_reserved = 9000, token_budget_settled = 9000",
            true,
            false,
            false,
        ),
    ] {
        let fixture = Fixture::new();
        fixture.issue(5);
        let connection = fixture.connection();
        connection
            .execute_batch(&format!(
                "PRAGMA ignore_check_constraints = ON; {mutation};"
            ))
            .unwrap();
        let telemetry = fixture.read().unwrap();
        assert_eq!(telemetry.accounting().is_none(), accounting, "{mutation}");
        assert_eq!(
            telemetry.committed_provider_effects().is_none(),
            effects,
            "{mutation}"
        );
        assert_eq!(
            telemetry.uncertain_attempts().is_none(),
            uncertain,
            "{mutation}"
        );
        assert!(telemetry.provider_approval_lease().is_some(), "{mutation}");
    }
}
