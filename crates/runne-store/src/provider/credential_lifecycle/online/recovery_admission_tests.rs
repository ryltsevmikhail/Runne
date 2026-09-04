include!("recovery_supersession_tests.rs");
include!("recovery_attempt_metadata_tests.rs");
#[cfg(unix)]
include!("recovery_process_kill_tests.rs");

fn recovery_request(
    store: &super::SqliteProviderCredentialLifecycleStore, proof: u8,
) -> runne_provider::CredentialCleanupRecoveryRequest {
    let authority = super::online_claim_test_support::measurements_for(store);
    let owner = CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap();
    let operation = store.prepared_cleanup_operations(owner, &provider()).unwrap().remove(0);
    let head = store.lifecycle_snapshot(&provider()).unwrap();
    runne_provider::CredentialCleanupRecoveryRequest::new(
        operation.operation_id(), owner,
        authority.release_manifest_digest(qualified_release(92).digest().as_bytes()).unwrap(),
        authority.protected_session_id([77; 32]).unwrap(),
        authority.desktop_supervisor_generation(1).unwrap(), 1,
        head.lifecycle_revision(), head.fence(),
        authority.continuation_binding_digest([proof; 32]).unwrap(), 30,
    )
}

#[test]
fn cleanup_recovery_admission_returns_one_witness_and_no_replay_authority() {
    let store = recovery_ledger_store();
    let request = recovery_request(&store, 99);
    let accepted = store.accept_cleanup_recovery(request.clone()).unwrap();
    assert_eq!(accepted.attempt(), 1);
    assert_eq!(accepted.issued_at(), 100);
    assert_eq!(accepted.expires_at(), 130);
    assert_eq!(accepted.request().continuation_digest(), digest(99));
    assert_eq!(accepted.operation().operation_id(), request.operation_id());
    store.enrollment_authority.validate_cleanup_recovery(&accepted).unwrap();
    assert!(store.accept_cleanup_recovery(request).is_err());
    assert!(store.accept_cleanup_recovery(recovery_request(&store, 98)).is_err());
    assert_eq!(store.connection.lock().unwrap().query_row(
        "SELECT COUNT(*) FROM credential_cleanup_recovery_attempts WHERE state='ACCEPTED'", [],
        |row| row.get::<_, i64>(0),
    ).unwrap(), 1);
}

#[test]
fn cleanup_recovery_two_connections_have_exactly_one_admission_winner() {
    let left = recovery_ledger_store();
    let path = std::path::PathBuf::from(left.connection.lock().unwrap().path().unwrap());
    let right = super::online_claim_test_support::reopen_test_store(&path, 100);
    let first = recovery_request(&left, 99);
    let second = recovery_request(&right, 98);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other_barrier = barrier.clone();
    let a = std::thread::spawn(move || {
        barrier.wait();
        left.accept_cleanup_recovery(first).map(|_| ())
    });
    let b = std::thread::spawn(move || {
        other_barrier.wait();
        right.accept_cleanup_recovery(second).map(|_| ())
    });
    let results = [a.join().unwrap(), b.join().unwrap()];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|r| **r == Err(runne_provider::CredentialLifecycleError::Conflict)).count(), 1);
    let connection = rusqlite::Connection::open(path).unwrap();
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM credential_cleanup_recovery_attempts", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
}

fn old_cleanup_claim(
    store: &super::SqliteProviderCredentialLifecycleStore,
) -> ClaimCredentialOperation {
    let operation = recovery_request(store, 99).operation_id();
    let receipt = issue_ticket(store, runne_provider::IssueCredentialTicketDigest::new(
        operation, digest(18), digest(19), 100,
    ).unwrap()).unwrap();
    seal_claim(store, ClaimCredentialOperation::new(receipt, digest(18), digest(19), digest(20), 1, 1).unwrap())
}

#[test]
fn cleanup_recovery_fences_old_ticket_and_rolls_back_fencing_on_insert_failure() {
    let store = recovery_ledger_store();
    let claim = old_cleanup_claim(&store);
    let request = recovery_request(&store, 99);
    store.connection.lock().unwrap().execute_batch(
        "CREATE TEMP TRIGGER reject_recovery BEFORE INSERT ON credential_cleanup_recovery_attempts
         BEGIN SELECT RAISE(ABORT, 'injected recovery failure'); END;",
    ).unwrap();
    assert!(store.accept_cleanup_recovery(request.clone()).is_err());
    {
        let connection = store.connection.lock().unwrap();
        let states: (String, String) = connection.query_row(
            "SELECT t.state, a.state FROM provider_credential_ticket_attempts t
             JOIN provider_credential_process_attachments a ON a.operation_id=t.operation_id
             WHERE t.operation_id=?1", [request.operation_id().as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(states, ("ISSUED".to_owned(), "ATTACHED".to_owned()));
        connection.execute_batch("DROP TRIGGER reject_recovery").unwrap();
    }
    let operation_id = request.operation_id();
    let _accepted = store.accept_cleanup_recovery(request).unwrap();
    assert!(store.claim(claim).is_err());
    assert!(store.attach_process(runne_provider::AttachCredentialProcess::new(
        operation_id, digest(19),
    ).unwrap()).is_err(), "a fenced continuation must not reattach as a fresh attempt");
    let connection = store.connection.lock().unwrap();
    assert_eq!(connection.query_row(
        "SELECT COUNT(*) FROM provider_credential_ticket_attempts WHERE ticket_digest=?1 AND state='TOMBSTONED'",
        [[18_u8; 32]], |row| row.get::<_, i64>(0),
    ).unwrap(), 1);
}

#[test]
fn cleanup_recovery_and_old_claim_cannot_both_win() {
    let left = recovery_ledger_store();
    let claim = old_cleanup_claim(&left);
    let path = std::path::PathBuf::from(left.connection.lock().unwrap().path().unwrap());
    let right = super::online_claim_test_support::reopen_test_store(&path, 100);
    let request = recovery_request(&right, 99);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other_barrier = barrier.clone();
    let a = std::thread::spawn(move || {
        barrier.wait();
        left.claim(claim).is_ok()
    });
    let b = std::thread::spawn(move || {
        other_barrier.wait();
        right.accept_cleanup_recovery(request).is_ok()
    });
    assert_ne!(a.join().unwrap(), b.join().unwrap());
}

#[test]
fn cleanup_recovery_reopen_does_not_reissue_a_lost_witness() {
    let store = recovery_ledger_store();
    let path = std::path::PathBuf::from(store.connection.lock().unwrap().path().unwrap());
    drop(store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap());
    drop(store);
    let reopened = super::online_claim_test_support::reopen_test_store(&path, 101);
    assert!(reopened.accept_cleanup_recovery(recovery_request(&reopened, 98)).is_err());
    let projection = reopened.prepared_cleanup_operations(
        CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(), &provider(),
    ).unwrap();
    assert_eq!(projection.len(), 1);
    assert_eq!(projection[0].state(), runne_provider::CredentialOperationState::Prepared);
    assert_eq!(reopened.connection.lock().unwrap().query_row(
        "SELECT COUNT(*) FROM credential_cleanup_recovery_attempts", [], |row| row.get::<_, i64>(0),
    ).unwrap(), 1);
}

#[test]
fn cleanup_recovery_rejects_foreign_authority_before_old_attempt_fencing() {
    let store = recovery_ledger_store();
    let _claim = old_cleanup_claim(&store);
    let path = std::path::PathBuf::from(store.connection.lock().unwrap().path().unwrap());
    let other = super::online_claim_test_support::reopen_test_store(&path, 100);
    assert!(store.accept_cleanup_recovery(recovery_request(&other, 99)).is_err());
    assert_eq!(store.connection.lock().unwrap().query_row(
        "SELECT COUNT(*) FROM provider_credential_ticket_attempts WHERE ticket_digest=?1 AND state='ISSUED'",
        [[18_u8; 32]], |row| row.get::<_, i64>(0),
    ).unwrap(), 1);
}

#[test]
fn cleanup_recovery_rejects_reused_continuation_without_fencing_live_ticket() {
    let store = recovery_ledger_store();
    let claim = old_cleanup_claim(&store);
    assert!(store.accept_cleanup_recovery(recovery_request(&store, 19)).is_err());
    assert!(store.claim(claim).is_ok(), "rejected recovery must preserve the old winner");
}

#[test]
fn cleanup_recovery_supersession_requires_expiry_and_exact_attempt() {
    let mut store = recovery_ledger_store();
    let old = store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap();
    store.now = std::sync::Arc::new(|| 129);
    assert!(store.supersede_cleanup_recovery(recovery_request(&store, 98), 1).is_err());
    store.now = std::sync::Arc::new(|| 130);
    for expected in [0, 2, u64::MAX] {
        assert!(store.supersede_cleanup_recovery(recovery_request(&store, 98), expected).is_err());
    }
    assert!(store.accept_cleanup_recovery(recovery_request(&store, 98)).is_err());
    let next = store.supersede_cleanup_recovery(recovery_request(&store, 98), 1).unwrap();
    assert_eq!((next.attempt(), next.issued_at(), next.expires_at()), (2, 130, 160));
    assert!(store.attach_cleanup_recovery(old).is_err());
    assert!(store.attach_cleanup_recovery(next).is_ok());
    let id = recovery_request(&store, 97).operation_id();
    let receipt = store.issue_ticket_attempt(runne_provider::IssueCredentialTicketDigest::new(
        id, digest(17), digest(98), 100,
    ).unwrap()).unwrap();
    assert_eq!(receipt.expires_at_high_water(), 160);
    let claim = super::online_claim_test_support::seal_claim_with_context(
        &store, ClaimCredentialOperation::new(receipt, digest(17), digest(98), digest(20), 1, 1).unwrap(),
        [92; 32], [77; 32],
    );
    store.claim(claim).unwrap();
    let connection = store.connection.lock().unwrap();
    let prior: (String, Vec<u8>) = connection.query_row(
        "SELECT state, terminal_digest FROM credential_cleanup_recovery_attempts WHERE attempt=1",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(prior, ("SUPERSEDED".to_owned(), vec![99; 32]));
    let state: String = connection.query_row(
        "SELECT state FROM credential_cleanup_recovery_attempts WHERE attempt=2", [], |row| row.get(0),
    ).unwrap();
    assert_eq!(state, "CONSUMED");
}
