use runne_provider::{AttachCredentialProcess, CredentialAuthorityPair, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentMeasurementAuthority, MeasuredQualificationAdmission, ProviderCredentialEnrollmentStore,
    QualificationSessionBinding};
use std::sync::Arc;
use super::{SqliteProviderCredentialLifecycleStore, online_test_support::{digest, operation, ticket}};

pub(super) fn setup() -> (SqliteProviderCredentialLifecycleStore, CredentialEnrollmentMeasurementAuthority) {
    setup_expiry(200)
}

fn setup_expiry(expiry: u64) -> (SqliteProviderCredentialLifecycleStore, CredentialEnrollmentMeasurementAuthority) {
    let path = tempfile::tempdir().unwrap().keep().join("qualified.sqlite");
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (issuer, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store = SqliteProviderCredentialLifecycleStore::open_with_authorities_and_now(
        &path, lifecycle, issuer, Arc::new(|| 100),
    ).unwrap();
    store.begin(super::online_test_support::begin_with_operation(1, 1, "qualified", 2, expiry)).unwrap();
    store.attach_process(AttachCredentialProcess::new(operation(1), digest(4)).unwrap()).unwrap();
    (store, measurements)
}

pub(super) fn admission(measurements: &CredentialEnrollmentMeasurementAuthority) -> MeasuredQualificationAdmission {
    admission_at(measurements, 100)
}

fn admission_at(measurements: &CredentialEnrollmentMeasurementAuthority, verified: u64) -> MeasuredQualificationAdmission {
    admission_bound(measurements, verified, operation(1), [1, 2, 3, 4])
}

fn admission_bound(measurements: &CredentialEnrollmentMeasurementAuthority, verified: u64,
    operation: runne_provider::CredentialOperationId, ids: [u8; 4]) -> MeasuredQualificationAdmission {
    measurements.measure_qualification_admission(
        super::qualification_fixture::facts(ids, 90, 180, verified),
        QualificationSessionBinding { protected_session: digest(10), continuation: digest(4),
            runtime_authority: [11; 16], database_generation: 1, launch_generation: 2,
            supervisor_generation: 3 }, operation, verified,
    ).unwrap()
}

#[test]
fn qualified_success_commits_one_actual_attempt_and_fence_with_sealed_receipt() {
    let (store, measurements) = setup();
    let measured = admission(&measurements);
    let expected = measured.fingerprint();
    let (issued, fence) = store.issue_ticket_attempt_with_qualification_fence(
        ticket(1, 1, 3, 4), measured,
    ).expect("canonical qualified atomic issuance");
    assert_eq!(issued.ticket_attempt().get(), 1);
    assert_eq!(fence.ticket_attempt(), issued.ticket_attempt());
    assert_eq!(issued.expires_at_high_water(), 180);
    assert_eq!(fence.effective_expires_at(), 180);
    assert_eq!(fence.fingerprint(), expected);
    assert!(measurements.validate_qualification_receipt(&fence).is_ok());
    let connection = store.connection.lock().unwrap();
    let rows: (i64, i64) = connection.query_row(
        "SELECT (SELECT count(*) FROM provider_credential_ticket_attempts),
        (SELECT count(*) FROM provider_qualification_admission_fences)", [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(rows, (1, 1));
}

#[test]
fn qualified_replay_and_second_attempt_never_rotate_the_existing_ticket() {
    let (store, measurements) = setup();
    store.issue_ticket_attempt_with_qualification_fence(ticket(1, 1, 3, 4), admission(&measurements)).unwrap();
    assert!(store.issue_ticket_attempt_with_qualification_fence(ticket(1, 2, 5, 4), admission(&measurements)).is_err());
    assert_eq!(super::online_test_support::ticket_state(&store, 1, 1), "ISSUED");
    assert_eq!(counts(&store), (1, 1));
}

#[test]
fn qualified_foreign_pair_wrong_operation_and_continuation_leave_no_rows() {
    let (store, measurements) = setup();
    let (_, foreign) = CredentialEnrollmentAuthorityPair::new().split();
    assert!(store.issue_ticket_attempt_with_qualification_fence(ticket(1, 1, 3, 4), admission(&foreign)).is_err());
    for input in [ticket(2, 1, 3, 4), ticket(1, 1, 3, 5)] {
        assert!(store.issue_ticket_attempt_with_qualification_fence(input, admission(&measurements)).is_err());
    }
    assert_eq!(counts(&store), (0, 0));
}

#[test]
fn qualified_insert_failure_rolls_back_ticket_and_preserves_previous_attempt() {
    let (store, measurements) = setup();
    store.connection.lock().unwrap().execute_batch(
        "CREATE TRIGGER test_reject_fence BEFORE INSERT ON provider_qualification_admission_fences
         BEGIN SELECT RAISE(ABORT,'test rejection'); END;",
    ).unwrap();
    assert!(store.issue_ticket_attempt_with_qualification_fence(ticket(1, 1, 3, 4), admission(&measurements)).is_err());
    assert_eq!(counts(&store), (0, 0));
    store.issue_ticket_attempt(ticket(1, 1, 6, 4)).unwrap();
    assert!(store.issue_ticket_attempt_with_qualification_fence(ticket(1, 2, 7, 4), admission(&measurements)).is_err());
    assert_eq!(counts(&store), (1, 0));
    assert_eq!(super::online_test_support::ticket_state(&store, 1, 1), "ISSUED");
}

pub(super) fn counts(store: &SqliteProviderCredentialLifecycleStore) -> (i64, i64) {
    store.connection.lock().unwrap().query_row(
        "SELECT (SELECT count(*) FROM provider_credential_ticket_attempts),
        (SELECT count(*) FROM provider_qualification_admission_fences)", [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap()
}

#[test]
fn qualified_authoritative_clock_and_all_deadlines_are_checked_before_insert() {
    for now in [89, 99, 180, 181, 200] {
        let (mut store, measurements) = setup();
        store.now = Arc::new(move || now);
        let measured = admission_at(&measurements, if now < 100 { 101 } else { 100 });
        assert!(store.issue_ticket_attempt_with_qualification_fence(ticket(1, 1, 3, 4), measured).is_err());
        assert_eq!(counts(&store), (0, 0));
    }
    let (store, measurements) = setup();
    store.connection.lock().unwrap().execute(
        "UPDATE provider_credential_authority_heads SET observed_at_high_water=180", [],
    ).unwrap();
    assert!(store.issue_ticket_attempt_with_qualification_fence(ticket(1, 1, 3, 4), admission(&measurements)).is_err());
    assert_eq!(counts(&store), (0, 0));
}

#[test]
fn qualified_deferred_commit_failure_rolls_back_both_rows() {
    let (mut store, measurements) = setup();
    store.now = Arc::new(|| 110);
    store.connection.lock().unwrap().execute_batch(
        "CREATE TABLE test_parent(id INTEGER PRIMARY KEY);
         CREATE TABLE test_child(id INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED);
         CREATE TRIGGER test_fail_commit AFTER INSERT ON provider_qualification_admission_fences
         BEGIN INSERT INTO test_child VALUES(1); END;",
    ).unwrap();
    assert!(store.issue_ticket_attempt_with_qualification_fence(ticket(1, 1, 3, 4), admission(&measurements)).is_err());
    assert_eq!(counts(&store), (0, 0));
    let observed: i64 = store.connection.lock().unwrap().query_row(
        "SELECT observed_at_high_water FROM provider_credential_authority_heads", [], |row| row.get(0),
    ).unwrap();
    assert_eq!(observed, 100);
}

#[test]
fn qualified_provider_ticket_and_receipt_cannot_outlive_begin_proof() {
    let (store, measurements) = setup_expiry(150);
    let (issued, receipt) = store.issue_ticket_attempt_with_qualification_fence(
        ticket(1, 1, 3, 4), admission(&measurements),
    ).unwrap();
    assert_eq!(issued.expires_at_high_water(), 150);
    assert_eq!(receipt.effective_expires_at(), 150);
}

#[test]
fn qualified_each_signed_id_or_nonce_rejects_new_operation_without_replacement() {
    use runne_provider::*;
    for duplicate in 0..4 {
        let (store, measurements) = setup();
        store.issue_ticket_attempt_with_qualification_fence(ticket(1, 1, 3, 4), admission(&measurements)).unwrap();
        let provider = ProviderId::new("deepseek").unwrap();
        let second = BeginCredentialOperation::new(
            runne_domain::id::CommandId::from_bytes([30; 16]),
            runne_domain::id::IdempotencyKey::new("second-qualified").unwrap(), operation(2),
            CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(), provider.clone(),
            CredentialOperationAction::Pair, Some(CredentialVersionRef::new(provider, 1).unwrap()), None,
            CredentialLifecycleRevision::new(1).unwrap(), CredentialFence::new(1).unwrap(), digest(40), 200,
        ).unwrap().with_qualified_release_tuple(super::online_test_support::qualified_release(92));
        store.begin(second).unwrap();
        store.attach_process(AttachCredentialProcess::new(operation(2), digest(4)).unwrap()).unwrap();
        let mut ids = [11, 12, 13, 14];
        ids[duplicate] = [1, 2, 3, 4][duplicate];
        let measured = admission_bound(&measurements, 100, operation(2), ids);
        assert!(store.issue_ticket_attempt_with_qualification_fence(ticket(2, 1, 5, 4), measured).is_err());
        assert_eq!(counts(&store), (1, 1));
        assert_eq!(super::online_test_support::ticket_state(&store, 1, 1), "ISSUED");
    }
}
