use super::fixture::Fixture;

#[test]
fn wrong_consumed_intent_makes_only_authority_unavailable() {
    let fixture = Fixture::new();
    fixture.issue(9);
    fixture
        .connection()
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON;
         UPDATE provider_effect_authorities SET consumed_intent_id = 'provider:wrong';",
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
fn authority_binding_mismatch_makes_only_authority_unavailable() {
    let fixture = Fixture::new();
    fixture.issue(10);
    fixture
        .connection()
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON;
         UPDATE provider_effect_authorities SET profile_digest = zeroblob(32);",
        )
        .unwrap();

    let telemetry = fixture.read().unwrap();
    assert!(telemetry.provider_effect_authorities().is_none());
    assert!(telemetry.accounting().is_some());
    assert!(telemetry.provider_approval_lease().is_some());
}

#[test]
fn malformed_runtime_flags_make_only_affected_data_unavailable() {
    for (mutation, authority, approval) in [
        ("capability_allowed = 2", true, false),
        ("capability_revocation_observed = 2", true, false),
        ("approval_allowed = 2", true, true),
        ("approval_revocation_observed = 2", true, true),
    ] {
        let fixture = Fixture::new();
        fixture
            .connection()
            .execute_batch(&format!(
                "PRAGMA ignore_check_constraints = ON;
             UPDATE provider_runtime_authority_state SET {mutation};"
            ))
            .unwrap();

        let telemetry = fixture.read().unwrap();
        assert_eq!(telemetry.provider_effect_authorities().is_none(), authority);
        assert_eq!(telemetry.provider_approval_lease().is_none(), approval);
        assert!(telemetry.accounting().is_some());
    }
}

#[test]
fn disabled_or_revoked_sets_remain_available_empty_aggregates() {
    for mutation in [
        "capability_allowed = 0",
        "approval_allowed = 0",
        "capability_revocation_observed = 1",
        "approval_revocation_observed = 1",
    ] {
        let fixture = Fixture::new();
        fixture
            .connection()
            .execute(
                &format!("UPDATE provider_runtime_authority_state SET {mutation}"),
                [],
            )
            .unwrap();

        let telemetry = fixture.read().unwrap();
        assert_eq!(
            telemetry.provider_effect_authorities().unwrap().values(),
            (0, 0, None)
        );
        if mutation.starts_with("approval") {
            assert_eq!(
                telemetry.provider_approval_lease().unwrap().values(),
                (0, 0, None)
            );
        } else {
            assert_eq!(telemetry.provider_approval_lease().unwrap().values().0, 1);
        }
    }
}

#[test]
fn unexpired_aggregates_project_nearest_expiry() {
    let fixture = Fixture::new();
    fixture.issue(11);
    fixture.issue_and_start_effect(12);
    fixture.connection().execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         UPDATE provider_execution_admissions SET expires_at = 1000001, approval_expires_at = 1000001;
         UPDATE provider_effect_authorities SET expires_at = 1000001;
         UPDATE provider_runtime_authority_state SET approval_expires_at = 1000001;
         UPDATE provider_effect_starts SET effect_started_at = 999881, effect_expires_at = 1000001;",
    ).unwrap();

    let telemetry = fixture.read().unwrap();
    assert_eq!(
        telemetry.provider_effect_authorities().unwrap().values(),
        (1, 0, Some(1_000_001))
    );
    assert_eq!(
        telemetry.provider_approval_lease().unwrap().values(),
        (1, 0, Some(1_000_001))
    );
    assert_eq!(
        telemetry.committed_provider_effects().unwrap().values(),
        (1, 0, Some(1_000_001))
    );
}

#[test]
fn localized_accounting_effect_and_uncertain_corruption_preserve_other_data() {
    let fixture = Fixture::new();
    fixture.issue_and_start_effect(13);
    fixture
        .connection()
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON;
         UPDATE provider_runtime_authority_state SET token_budget_limit = -1;
         UPDATE provider_effect_starts SET state = 2;
         UPDATE provider_dispatch_attempts SET state = 99;",
        )
        .unwrap();

    let telemetry = fixture.read().unwrap();
    assert!(telemetry.accounting().is_none());
    assert!(telemetry.committed_provider_effects().is_none());
    assert!(telemetry.uncertain_attempts().is_none());
    assert!(telemetry.provider_approval_lease().is_some());
}
