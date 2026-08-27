use rusqlite::Connection;

use super::ProviderAuthorityIssueOutcome;
use super::authority_test_support::{Fixture, prepare_request};

#[test]
fn online_claim_provider_mapping_rejects_direct_mutation_after_authorized_issue() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture
        .store
        .issue(
            fixture.launch(),
            &prepare_request(fixture.launch(), &fixture.path, 72),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh issue"),
    };
    let attempt = admission.claim().attempt_id.as_bytes().to_vec();
    let connection = Connection::open(&fixture.path).unwrap();
    let before: String = connection
        .query_row(
            "SELECT provider_id FROM provider_online_dispatch_claim_providers
             WHERE dispatch_attempt_id=?1",
            [&attempt],
            |row| row.get(0),
        )
        .unwrap();

    assert!(
        connection
            .execute(
                "UPDATE provider_online_dispatch_claim_providers
             SET provider_id='other-provider' WHERE dispatch_attempt_id=?1",
                [&attempt],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM provider_online_dispatch_claim_providers WHERE dispatch_attempt_id=?1",
                [&attempt],
            )
            .is_err()
    );
    let after: String = connection
        .query_row(
            "SELECT provider_id FROM provider_online_dispatch_claim_providers
             WHERE dispatch_attempt_id=?1",
            [&attempt],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn raw_sql_cannot_attach_another_provider_after_removing_a_current_mapping() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture
        .store
        .issue(
            fixture.launch(),
            &prepare_request(fixture.launch(), &fixture.path, 73),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh issue"),
    };
    let attempt = admission.claim().attempt_id.as_bytes().to_vec();
    let connection = Connection::open(&fixture.path).unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_online_dispatch_claim_provider_no_delete")
        .unwrap();
    connection
        .execute(
            "DELETE FROM provider_online_dispatch_claim_providers WHERE dispatch_attempt_id=?1",
            [&attempt],
        )
        .unwrap();

    assert!(connection
        .execute(
            "INSERT INTO provider_online_dispatch_claim_providers (dispatch_attempt_id, provider_id)
             VALUES (?1, 'other-provider')",
            [&attempt],
        )
        .is_err());
}

#[test]
fn issuance_evidence_rejects_raw_insert_update_and_delete() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture
        .store
        .issue(
            fixture.launch(),
            &prepare_request(fixture.launch(), &fixture.path, 75),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh issue"),
    };
    let attempt = admission.claim().attempt_id.as_bytes().to_vec();
    let connection = Connection::open(&fixture.path).unwrap();

    assert!(
        connection
            .execute(
                "INSERT INTO provider_online_dispatch_issuance_evidence
             (dispatch_attempt_id, provider_id, authority_id, authority_revision, issued_at)
             VALUES (?1, 'other-provider', zeroblob(16), 1, 0)",
                [&attempt],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE provider_online_dispatch_issuance_evidence
             SET provider_id='other-provider' WHERE dispatch_attempt_id=?1",
                [&attempt],
            )
            .is_err()
    );
    assert!(connection
        .execute(
            "DELETE FROM provider_online_dispatch_issuance_evidence WHERE dispatch_attempt_id=?1",
            [&attempt],
        )
        .is_err());
}

#[test]
fn failed_issue_clears_the_scoped_online_issuance_guard() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let rejected = prepare_request(fixture.launch(), &fixture.path, 76);
    let retry = prepare_request(fixture.launch(), &fixture.path, 77);
    let connection = Connection::open(&fixture.path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER injected_online_claim_failure
             BEFORE INSERT ON provider_online_dispatch_claim_providers
             BEGIN SELECT RAISE(ABORT, 'injected issue failure'); END;",
        )
        .unwrap();
    assert_eq!(
        fixture.store.issue(fixture.launch(), &rejected),
        Err(runne_application::provider::ProviderAdmissionError::RepositoryFailure)
    );
    connection
        .execute_batch("DROP TRIGGER injected_online_claim_failure")
        .unwrap();
    assert!(matches!(
        fixture.store.issue(fixture.launch(), &retry),
        Ok(ProviderAuthorityIssueOutcome::Winner(_))
    ));
}
