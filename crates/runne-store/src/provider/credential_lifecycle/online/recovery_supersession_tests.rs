#[test]
fn cleanup_recovery_supersession_fences_old_ticket_and_rolls_back_on_failure() {
    let mut store = recovery_ledger_store();
    let accepted = store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap();
    let receipt = issue_recovery_ticket(&store, accepted, 30);
    let claim = recovery_claim(&store, receipt, [92; 32], [77; 32], 1, 1);
    store.now = std::sync::Arc::new(|| 130);
    assert!(store.supersede_cleanup_recovery(recovery_request(&store, 99), 1).is_err());
    store.connection.lock().unwrap().execute_batch(
        "CREATE TEMP TRIGGER fail_supersession BEFORE INSERT ON credential_cleanup_recovery_attempts
         BEGIN SELECT RAISE(ABORT, 'injected supersession failure'); END;",
    ).unwrap();
    assert!(store.supersede_cleanup_recovery(recovery_request(&store, 98), 1).is_err());
    {
        let connection = store.connection.lock().unwrap();
        let states: (String, Option<Vec<u8>>, String, String) = connection.query_row(
            "SELECT r.state, r.terminal_digest, t.state, a.state
             FROM credential_cleanup_recovery_attempts r
             JOIN provider_credential_ticket_attempts t USING(operation_id)
             JOIN provider_credential_process_attachments a USING(operation_id)", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert_eq!(states, ("ACCEPTED".into(), None, "ISSUED".into(), "ATTACHED".into()));
        connection.execute_batch("DROP TRIGGER fail_supersession").unwrap();
    }
    let next = store.supersede_cleanup_recovery(recovery_request(&store, 98), 1).unwrap();
    assert!(store.claim(claim).is_err());
    store.attach_cleanup_recovery(next).unwrap();
    let connection = store.connection.lock().unwrap();
    let states: (String, String) = connection.query_row(
        "SELECT t.state, a.state FROM provider_credential_ticket_attempts t
         JOIN provider_credential_process_attachments a USING(operation_id)
         WHERE a.continuation_binding_digest=?1", [[99_u8; 32]],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(states, ("TOMBSTONED".into(), "TOMBSTONED".into()));
}

#[test]
fn cleanup_recovery_supersession_after_reopen_has_one_cas_winner() {
    let store = recovery_ledger_store();
    drop(store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap());
    let path = std::path::PathBuf::from(store.connection.lock().unwrap().path().unwrap());
    drop(store);
    let left = super::online_claim_test_support::reopen_test_store(&path, 131);
    let right = super::online_claim_test_support::reopen_test_store(&path, 131);
    let first = recovery_request(&left, 98);
    let second = recovery_request(&right, 97);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other = barrier.clone();
    let a = std::thread::spawn(move || {
        barrier.wait();
        left.supersede_cleanup_recovery(first, 1).map(|a| a.attempt())
    });
    let b = std::thread::spawn(move || {
        other.wait();
        right.supersede_cleanup_recovery(second, 1).map(|a| a.attempt())
    });
    let results = [a.join().unwrap(), b.join().unwrap()];
    assert_eq!(results.iter().filter(|r| **r == Ok(2)).count(), 1);
    assert_eq!(results.iter().filter(|r| **r == Err(runne_provider::CredentialLifecycleError::Conflict)).count(), 1);
}

#[test]
fn cleanup_recovery_supersession_cannot_reset_claimed_operation() {
    let mut store = recovery_ledger_store();
    let request = recovery_request(&store, 98);
    let accepted = store.accept_cleanup_recovery(recovery_request(&store, 99)).unwrap();
    let receipt = issue_recovery_ticket(&store, accepted, 30);
    store.claim(recovery_claim(&store, receipt, [92; 32], [77; 32], 1, 1)).unwrap();
    store.now = std::sync::Arc::new(|| 131);
    assert!(store.supersede_cleanup_recovery(request, 1).is_err());
    let state: String = store.connection.lock().unwrap().query_row(
        "SELECT state FROM credential_cleanup_recovery_attempts", [], |row| row.get(0),
    ).unwrap();
    assert_eq!(state, "CONSUMED");
}
