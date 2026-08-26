use std::time::Duration;

use runne_application::provider::ProviderAdmissionError;
use rusqlite::{Connection, TransactionBehavior};

use super::ProviderAuthorityIssueOutcome;
use super::authority_test_support::Fixture;

#[test]
fn pre_v24_binding_cannot_start_after_v24_authority_takeover() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    let connection = Connection::open(&fixture.path).unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_authority_heads
             (provider_id, lifecycle_revision, credential_fence,
              readiness_revision, next_credential_version)
             VALUES ('fixture-provider', 1, 1, 1, 1)",
            [],
        )
        .unwrap();

    assert_eq!(
        fixture.store.start_effect(admission.claim(), &credential),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    let rows: (i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM provider_effect_starts),
                (SELECT COUNT(*) FROM security_audit_pre_effect)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(rows, (0, 0));
}

#[test]
fn takeover_on_a_second_connection_closes_effect_start_after_commit() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(2).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    let mut takeover = Connection::open(&fixture.path).unwrap();
    takeover.busy_timeout(Duration::from_secs(5)).unwrap();
    let transaction = takeover
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction
        .execute(
            "INSERT INTO provider_credential_authority_heads
             (provider_id, lifecycle_revision, credential_fence,
              readiness_revision, next_credential_version)
             VALUES ('fixture-provider', 1, 1, 1, 1)",
            [],
        )
        .unwrap();

    let result = std::thread::scope(|scope| {
        let (started, wait_started) = std::sync::mpsc::sync_channel(0);
        let pending = scope.spawn(move || {
            started.send(()).unwrap();
            fixture.store.start_effect(admission.claim(), &credential)
        });
        wait_started.recv().unwrap();
        transaction.commit().unwrap();
        pending.join().unwrap()
    });

    assert_eq!(result, Err(ProviderAdmissionError::AuthorityDenied));
    let rows: (i64, i64) = takeover
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM provider_effect_starts),
                (SELECT COUNT(*) FROM security_audit_pre_effect)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(rows, (0, 0));
}
