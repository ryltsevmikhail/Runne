#[test]
fn expired_cleanup_metadata_is_owner_scoped_read_only_and_exact_at_expiry() {
    let mut store = recovery_ledger_store();
    let request = recovery_request(&store, 99);
    let owner = request.owner();
    let operation = request.operation_id();
    assert_eq!(store.expired_cleanup_recovery_attempt(owner, operation), Ok(None));
    let accepted = store.accept_cleanup_recovery(request).unwrap();
    store.now = std::sync::Arc::new(|| 129);
    assert_eq!(store.expired_cleanup_recovery_attempt(owner, operation), Ok(None));
    store.now = std::sync::Arc::new(|| 130);
    assert_eq!(store.expired_cleanup_recovery_attempt(owner, operation), Ok(Some(1)));
    assert_eq!(store.expired_cleanup_recovery_attempt(owner, operation), Ok(Some(1)));
    assert!(store.expired_cleanup_recovery_attempt(CredentialInstallationOwnerId::from_bytes([43;32]).unwrap(), operation).is_err());
    assert_eq!(store.connection.lock().unwrap().query_row(
        "SELECT state FROM credential_cleanup_recovery_attempts WHERE attempt=1", [], |row| row.get::<_, String>(0)
    ).unwrap(), "ACCEPTED");
    assert_eq!(store.load_operation(operation).unwrap().state(), runne_provider::CredentialOperationState::Prepared);
    drop(accepted);
    let next = store.supersede_cleanup_recovery(recovery_request(&store, 98), 1).unwrap();
    assert_eq!(next.attempt(), 2);
    assert_eq!(store.expired_cleanup_recovery_attempt(owner, operation), Ok(None));
    store.now = std::sync::Arc::new(|| 160);
    assert_eq!(store.expired_cleanup_recovery_attempt(owner, operation), Ok(Some(2)));
}

#[test]
fn expired_cleanup_metadata_never_offers_claimed_work_for_supersession() {
    let mut store = recovery_ledger_store();
    let request = recovery_request(&store, 99);
    let owner = request.owner();
    let operation = request.operation_id();
    let accepted = store.accept_cleanup_recovery(request).unwrap();
    let receipt = issue_recovery_ticket(&store, accepted, 30);
    let claim = recovery_claim(&store, receipt, [92; 32], [77; 32], 1, 1);
    store.claim(claim).unwrap();
    store.now = std::sync::Arc::new(|| 160);
    assert_eq!(store.expired_cleanup_recovery_attempt(owner, operation), Ok(None));
    assert_eq!(store.load_operation(operation).unwrap().state(), runne_provider::CredentialOperationState::Claimed);
}

#[test]
fn expired_recovery_ticket_issue_persists_clock_floor_across_reopen() {
    let mut store = recovery_ledger_store();
    let request = recovery_request(&store, 99);
    let operation = request.operation_id();
    let accepted = store.accept_cleanup_recovery(request).unwrap();
    store.attach_cleanup_recovery(accepted).unwrap();
    let issue = || runne_provider::IssueCredentialTicketDigest::new(
        operation, digest(18), digest(99), 30,
    ).unwrap();
    store.now = std::sync::Arc::new(|| 130);
    assert_eq!(store.issue_ticket_attempt(issue()).err(),
        Some(runne_provider::CredentialLifecycleError::StaleLease));
    let path = std::path::PathBuf::from(store.connection.lock().unwrap().path().unwrap());
    drop(store);
    let reopened = super::online_claim_test_support::reopen_test_store(&path, 120);
    assert_eq!(reopened.issue_ticket_attempt(issue()).err(),
        Some(runne_provider::CredentialLifecycleError::StaleLease));
    let tickets: i64 = reopened.connection.lock().unwrap().query_row(
        "SELECT COUNT(*) FROM provider_credential_ticket_attempts WHERE operation_id=?1",
        [operation.as_bytes().as_slice()], |row| row.get(0),
    ).unwrap();
    assert_eq!(tickets, 0, "expired issue must not leave a usable ticket");
    let next = reopened.supersede_cleanup_recovery(recovery_request(&reopened, 98), 1).unwrap();
    assert_eq!((next.attempt(), next.issued_at(), next.expires_at()), (2, 130, 160));
}

#[test]
fn expired_recovery_attachment_persists_clock_floor_across_reopen() {
    let mut store = recovery_ledger_store();
    let request = recovery_request(&store, 99);
    let owner = request.owner();
    let operation = request.operation_id();
    let accepted = store.accept_cleanup_recovery(request).unwrap();
    store.now = std::sync::Arc::new(|| 130);
    assert_eq!(store.attach_cleanup_recovery(accepted),
        Err(runne_provider::CredentialLifecycleError::StaleLease));
    let path = std::path::PathBuf::from(store.connection.lock().unwrap().path().unwrap());
    drop(store);

    let reopened = super::online_claim_test_support::reopen_test_store(&path, 120);
    assert_eq!(reopened.expired_cleanup_recovery_attempt(owner, operation), Ok(Some(1)));
    let next = reopened.supersede_cleanup_recovery(recovery_request(&reopened, 98), 1).unwrap();
    assert_eq!((next.attempt(), next.issued_at(), next.expires_at()), (2, 130, 160));
    reopened.attach_cleanup_recovery(next).unwrap();
    let connection = reopened.connection.lock().unwrap();
    let old: (String, Vec<u8>) = connection.query_row(
        "SELECT state, terminal_digest FROM credential_cleanup_recovery_attempts WHERE attempt=1",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(old, ("SUPERSEDED".to_owned(), vec![99; 32]));
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_credential_process_attachments
         WHERE operation_id=?1 AND continuation_binding_digest=?2",
        rusqlite::params![operation.as_bytes().as_slice(), [99_u8; 32]],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(count, 0, "expired continuation must never become attached");
}
