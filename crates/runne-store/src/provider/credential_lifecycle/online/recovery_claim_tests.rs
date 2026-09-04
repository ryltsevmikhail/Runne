fn recovery_claim(
    store: &super::SqliteProviderCredentialLifecycleStore,
    receipt: runne_provider::IssuedCredentialTicketAttempt,
    release: [u8; 32], session: [u8; 32], database: u64, supervisor: u64,
) -> ClaimCredentialOperation {
    super::online_claim_test_support::seal_claim_with_context(
        store,
        ClaimCredentialOperation::new(receipt, digest(18), digest(99), digest(20), database, supervisor).unwrap(),
        release, session,
    )
}

fn issue_recovery_ticket(
    store: &super::SqliteProviderCredentialLifecycleStore,
    accepted: runne_provider::AcceptedCredentialCleanupRecovery, ttl: i64,
) -> runne_provider::IssuedCredentialTicketAttempt {
    let operation = accepted.operation().operation_id();
    assert!(store.attach_process(runne_provider::AttachCredentialProcess::new(
        operation, digest(99),
    ).unwrap()).is_err(), "metadata and proof digest alone cannot attach recovery");
    store.attach_cleanup_recovery(accepted).unwrap();
    store.issue_ticket_attempt(runne_provider::IssueCredentialTicketDigest::new(
        operation, digest(18), digest(99), ttl,
    ).unwrap()).unwrap()
}

#[test]
fn cleanup_recovery_claim_consumes_the_exact_lease_atomically() {
    let store = recovery_ledger_store();
    let accepted = store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap();
    let receipt = issue_recovery_ticket(&store, accepted, 100);
    assert_eq!(receipt.expires_at_high_water(), 130, "ticket cannot outlive its recovery lease");
    let claim = recovery_claim(&store, receipt, qualified_release(92).digest().as_bytes(), [77; 32], 1, 1);
    store.claim(claim).unwrap();
    let state: (String, Option<Vec<u8>>) = store.connection.lock().unwrap().query_row(
        "SELECT state, terminal_digest FROM credential_cleanup_recovery_attempts", [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(state, ("CONSUMED".to_owned(), Some(vec![99; 32])));
}

#[test]
fn cleanup_recovery_claim_rejects_changed_session_release_or_generation() {
    for (release, session, database, supervisor) in [
        ([92; 32], [78; 32], 1, 1),
        ([93; 32], [77; 32], 1, 1),
        ([92; 32], [77; 32], 2, 1),
        ([92; 32], [77; 32], 1, 2),
    ] {
        let store = recovery_ledger_store();
        let accepted = store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap();
        let receipt = issue_recovery_ticket(&store, accepted, 30);
        assert!(store.claim(recovery_claim(&store, receipt, release, session, database, supervisor)).is_err());
        let state: String = store.connection.lock().unwrap().query_row(
            "SELECT state FROM credential_cleanup_recovery_attempts", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(state, "ACCEPTED");
    }
}

#[test]
fn cleanup_recovery_attaches_and_claims_after_original_begin_expiry() {
    let mut store = store();
    complete_pair(&store, 10, "first-pair");
    store.begin(BeginCredentialOperation::new(
        CommandId::from_bytes([81; 16]), IdempotencyKey::new("expired-revoke").unwrap(),
        operation(81), CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        provider(), CredentialOperationAction::Revoke, None,
        Some(CredentialVersionRef::new(provider(), 1).unwrap()),
        CredentialLifecycleRevision::new(2).unwrap(), CredentialFence::new(2).unwrap(),
        digest(82), 200,
    ).unwrap().with_qualified_release_tuple(qualified_release(92))).unwrap();
    store.now = std::sync::Arc::new(|| 201);
    let accepted = store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap();
    store.attach_cleanup_recovery(accepted).unwrap();
    let receipt = store.issue_ticket_attempt(runne_provider::IssueCredentialTicketDigest::new(
        operation(81), digest(18), digest(99), 100,
    ).unwrap()).unwrap();
    assert_eq!(receipt.expires_at_high_water(), 231);
    store.claim(recovery_claim(&store, receipt, [92; 32], [77; 32], 1, 1)).unwrap();
}

#[test]
fn cleanup_recovery_consumption_rolls_back_with_failed_ticket_claim() {
    let store = recovery_ledger_store();
    let accepted = store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap();
    let receipt = issue_recovery_ticket(&store, accepted, 30);
    store.connection.lock().unwrap().execute_batch(
        "CREATE TEMP TRIGGER fail_recovery_claim BEFORE UPDATE ON provider_credential_ticket_attempts
         WHEN NEW.state='CLAIMED' BEGIN SELECT RAISE(ABORT, 'injected claim failure'); END;",
    ).unwrap();
    assert!(store.claim(recovery_claim(&store, receipt, [92; 32], [77; 32], 1, 1)).is_err());
    let states: (String, Option<Vec<u8>>, String, String) = store.connection.lock().unwrap().query_row(
        "SELECT r.state, r.terminal_digest, o.state, t.state
         FROM credential_cleanup_recovery_attempts r
         JOIN provider_credential_operations o ON o.operation_id=r.operation_id
         JOIN provider_credential_ticket_attempts t ON t.operation_id=r.operation_id", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap();
    assert_eq!(states, ("ACCEPTED".to_owned(), None, "PREPARED".to_owned(), "ISSUED".to_owned()));
}

#[test]
fn cleanup_recovery_expired_claim_cannot_consume_lease() {
    let mut store = recovery_ledger_store();
    let accepted = store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap();
    let receipt = issue_recovery_ticket(&store, accepted, 30);
    let claim = recovery_claim(&store, receipt, [92; 32], [77; 32], 1, 1);
    store.now = std::sync::Arc::new(|| 130);
    assert!(store.claim(claim).is_err());
    let state: String = store.connection.lock().unwrap().query_row(
        "SELECT state FROM credential_cleanup_recovery_attempts", [], |row| row.get(0),
    ).unwrap();
    assert_eq!(state, "ACCEPTED");
}

#[test]
fn cleanup_recovery_sql_ticket_cannot_outlive_accepted_lease() {
    let store = recovery_ledger_store();
    let accepted = store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap();
    let id = accepted.operation().operation_id();
    store.attach_cleanup_recovery(accepted).unwrap();
    let connection = store.connection.lock().unwrap();
    let sql = "INSERT INTO provider_credential_ticket_attempts
        (operation_id, attempt, ticket_digest, continuation_binding_digest, issued_at, expires_at, state)
        VALUES (?1, 1, ?2, ?3, 100, ?4, 'ISSUED')";
    assert!(connection.execute(sql, rusqlite::params![
        id.as_bytes().as_slice(), [18_u8; 32], [99_u8; 32], 131,
    ]).is_err());
    assert_eq!(connection.execute(sql, rusqlite::params![
        id.as_bytes().as_slice(), [18_u8; 32], [99_u8; 32], 130,
    ]).unwrap(), 1);
}
