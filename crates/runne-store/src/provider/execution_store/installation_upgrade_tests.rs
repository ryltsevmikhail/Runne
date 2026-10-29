use super::authority_test_support::{Fixture, authority_row};
use super::*;
use runne_application::provider::ProviderLeaseBindingKind;

fn fixture() -> Fixture {
    let mut f = Fixture::new(1000);
    f.config.activation_binding_kind = ProviderLeaseBindingKind::ExternalOwnerPrivate;
    f.install();
    f
}
fn next(
    f: &Fixture,
) -> (
    ProviderRuntimeAuthorityConfig,
    ProviderRuntimeAuthorityConfig,
) {
    let mut before = f.config.clone();
    before.generation += 1;
    before.fencing_token += 1;
    let mut after = before.clone();
    after.activation_binding_digest = [91; 32];
    after.owner_id = "new-owner-binding".into();
    after.capability_grant_id = "new-capability-binding".into();
    after.approval_id = "new-approval-binding".into();
    (before, after)
}

#[test]
fn installation_upgrade_preserves_budgets_and_is_idempotent() {
    let f = fixture();
    let (before, after) = next(&f);
    let utilization = f.store.utilization().unwrap();
    assert!(f.store.activate_runtime_launch(&after).is_err());
    f.store
        .upgrade_external_installation(&before, &after)
        .unwrap();
    let row = authority_row(&f.path);
    assert_eq!(f.store.utilization().unwrap(), utilization);
    f.store
        .upgrade_external_installation(&before, &after)
        .unwrap();
    assert_eq!(authority_row(&f.path), row);
    assert!(f.store.activate_runtime_launch(&after).is_ok());
    assert!(f.store.activate_runtime_launch(&before).is_err());
}

#[test]
fn installation_upgrade_rejects_policy_changes_and_wrong_previous_binding() {
    let f = fixture();
    let (before, after) = next(&f);
    for change in [
        |c: &mut ProviderRuntimeAuthorityConfig| c.token_budget_limit += 1,
        |c: &mut ProviderRuntimeAuthorityConfig| c.profile_digest = [71; 32],
        |c: &mut ProviderRuntimeAuthorityConfig| c.capability_allowed = false,
        |c: &mut ProviderRuntimeAuthorityConfig| c.principal_id = "other".into(),
    ] {
        let mut bad = after.clone();
        change(&mut bad);
        let row = authority_row(&f.path);
        assert!(
            f.store
                .upgrade_external_installation(&before, &bad)
                .is_err()
        );
        assert_eq!(authority_row(&f.path), row);
    }
    let mut wrong = before.clone();
    wrong.activation_binding_digest = [72; 32];
    assert!(
        f.store
            .upgrade_external_installation(&wrong, &after)
            .is_err()
    );
}

#[test]
fn installation_upgrade_rejects_unfinished_dispatch_without_effect() {
    let f = fixture();
    f.issue(1).unwrap();
    let row = authority_row(&f.path);
    let (before, after) = next(&f);
    assert!(
        f.store
            .upgrade_external_installation(&before, &after)
            .is_err()
    );
    assert_eq!(authority_row(&f.path), row);
}

#[test]
fn installation_upgrade_transaction_failure_retains_old_binding() {
    let f = fixture();
    let connection = rusqlite::Connection::open(&f.path).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_upgrade BEFORE UPDATE ON provider_runtime_authority_state BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;").unwrap();
    let row = authority_row(&f.path);
    let (before, after) = next(&f);
    assert!(
        f.store
            .upgrade_external_installation(&before, &after)
            .is_err()
    );
    assert_eq!(authority_row(&f.path), row);
    connection
        .execute_batch("DROP TRIGGER fail_upgrade;")
        .unwrap();
    f.store
        .upgrade_external_installation(&before, &after)
        .unwrap();
}

#[test]
fn installation_upgrade_preserves_credential_history_and_rejects_pending() {
    let f = fixture();
    let conn = rusqlite::Connection::open(&f.path).unwrap();
    conn.execute_batch(
        "INSERT INTO provider_credential_authority_heads (provider_id,lifecycle_revision,credential_fence,readiness_revision,next_credential_version) VALUES ('deepseek',1,1,1,1); INSERT INTO provider_credential_operations
        (operation_id, installation_owner_id, provider_id, action, command_id,
         idempotency_key, expected_lifecycle_revision, expected_credential_fence,
         allocated_credential_version, allocated_ref_digest, state, begin_proof_digest,
         created_at, updated_at, begin_proof_expires_at_high_water, qualified_release_tuple_digest)
        VALUES (randomblob(16),randomblob(32),'deepseek','PAIR',randomblob(16),
        'synthetic-upgrade',1,1,1,randomblob(32),'PREPARED',randomblob(32),1,1,10000,randomblob(32));",
    )
    .unwrap();
    let (before, after) = next(&f);
    let row = authority_row(&f.path);
    assert!(
        f.store
            .upgrade_external_installation(&before, &after)
            .is_err()
    );
    assert_eq!(authority_row(&f.path), row);
    conn.execute_batch("UPDATE provider_credential_operations SET state='CANCELLED',terminal_disposition='CANCELLED';
        UPDATE provider_runtime_authority_state SET token_budget_settled=7, cost_budget_settled_micros=3;")
        .unwrap();
    let utilization = f.store.utilization().unwrap();
    f.store
        .upgrade_external_installation(&before, &after)
        .unwrap();
    assert_eq!(f.store.utilization().unwrap(), utilization);
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM provider_credential_operations WHERE state='CANCELLED'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    let updated = authority_row(&f.path);
    assert_eq!(updated.capability_expires_at, row.capability_expires_at);
    assert_eq!(updated.approval_expires_at, row.approval_expires_at);
}

#[test]
fn installation_upgrade_never_resurrects_revoked_authority() {
    let f = fixture();
    let conn = rusqlite::Connection::open(&f.path).unwrap();
    conn.execute_batch("UPDATE provider_runtime_authority_state SET capability_allowed=0, capability_revocation_observed=1;").unwrap();
    let row = authority_row(&f.path);
    let (before, after) = next(&f);
    assert!(
        f.store
            .upgrade_external_installation(&before, &after)
            .is_err()
    );
    assert_eq!(authority_row(&f.path), row);
}
