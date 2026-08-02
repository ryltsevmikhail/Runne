#[tokio::test]
async fn race_revocation_wins_over_dispatch() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let dispatch = valid_tx("dispatch-before-revocation", "permit-revoked-grant");
    first_store.commit_pre_effect(&dispatch).unwrap();
    let mut revoked_grant = dispatch.clone();
    revoked_grant.authorization_decision.grant_id = "grant-revoked".into();

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        revoked_grant.clone(),
        second_store,
        revoked_grant,
    )
    .await;

    assert!(matches!(
        first_result,
        Err(AtomicTransactionError::ReplayConflict)
    ));
    assert!(matches!(
        second_result,
        Err(AtomicTransactionError::ReplayConflict)
    ));
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_dispatch_commit_wins_before_revocation_and_remains_committed() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let dispatch = valid_tx("intent-before-revoke", "permit-before-revoke");
    first_store.commit_pre_effect(&dispatch).unwrap();

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        dispatch.clone(),
        second_store,
        dispatch,
    )
    .await;

    assert!(first_result.is_ok());
    assert!(second_result.is_ok());
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_cancel_fences_new_dispatch() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let cancelled_run = valid_tx("cancel-run-cancel-first", "run-cancel-first");
    first_store.commit_pre_effect(&cancelled_run).unwrap();

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        valid_tx("dispatch-after-cancel-a", "run-cancel-first"),
        second_store,
        valid_tx("dispatch-after-cancel-b", "run-cancel-first"),
    )
    .await;

    assert!(matches!(
        first_result,
        Err(AtomicTransactionError::PermitIntentConflict)
    ));
    assert!(matches!(
        second_result,
        Err(AtomicTransactionError::PermitIntentConflict)
    ));
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_dispatch_claim_wins_before_cancel_and_new_dispatch_is_fenced() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    first_store
        .commit_pre_effect(&valid_tx("dispatch-first", "run-dispatch-first"))
        .unwrap();

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        valid_tx("cancel-after-dispatch-a", "run-dispatch-first"),
        second_store,
        valid_tx("cancel-after-dispatch-b", "run-dispatch-first"),
    )
    .await;

    assert!(matches!(
        first_result,
        Err(AtomicTransactionError::PermitIntentConflict)
    ));
    assert!(matches!(
        second_result,
        Err(AtomicTransactionError::PermitIntentConflict)
    ));
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_dual_approval_idempotent() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let approval = valid_tx("approval-approval-a", "approval-a");

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        approval.clone(),
        second_store,
        approval,
    )
    .await;

    assert_eq!(first_result, second_result);
    assert!(matches!(
        first_result,
        Ok(PreEffectTransactionOutcome::Committed { ref intent_id }) if intent_id == "approval-approval-a"
    ));
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_concurrent_grants_different_ids() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let mut first_grant = valid_tx("grant-a", "permit-grant-a");
    first_grant.authorization_decision.grant_id = "grant-a".into();
    let mut second_grant = valid_tx("grant-b", "permit-grant-b");
    second_grant.authorization_decision.grant_id = "grant-b".into();

    let (first_result, second_result) =
        concurrent_commits(first_store.clone(), first_grant, second_store, second_grant).await;

    assert!(first_result.is_ok());
    assert!(second_result.is_ok());
    assert_eq!(first_store.committed_count().unwrap(), 2);
}

#[tokio::test]
async fn race_concurrent_replay_with_changed_payload_is_rejected() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let original = valid_tx("intent-changed-replay", "permit-changed-replay");
    let mut changed = original.clone();
    changed.authorization_decision.reason = "changed authorization".into();

    let (first_result, second_result) =
        concurrent_commits(first_store.clone(), original, second_store, changed).await;
    let outcomes = [first_result, second_result];

    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(AtomicTransactionError::ReplayConflict)))
            .count(),
        1
    );
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_cleanup_before_restart() {
    let pool = Arc::new(tokio::sync::Mutex::new(CleanupPool::new(1)));
    pool.lock()
        .await
        .allocate_for_generation("cleanup-1".into(), Generation::INITIAL)
        .unwrap();
    pool.lock()
        .await
        .release_for_generation("cleanup-1", Generation::INITIAL)
        .unwrap();

    assert_eq!(
        pool.lock().await.reservation("cleanup-1").unwrap().state,
        CleanupState::Released
    );
    assert_eq!(pool.lock().await.available(), 1);
}

#[tokio::test]
async fn race_restart_before_cleanup() {
    let mut pool = CleanupPool::new(1);
    pool.allocate_for_generation("cleanup-2".into(), Generation::INITIAL)
        .unwrap();

    let result = pool.release_for_generation("cleanup-2", Generation::INITIAL.next());

    assert!(matches!(result, Err(CleanupError::StaleGeneration)));
    assert_eq!(pool.available(), 0);
    assert_eq!(
        pool.reservation("cleanup-2").unwrap().state,
        CleanupState::Allocated
    );
}

#[tokio::test]
async fn race_secret_resolve_before_revoke() {
    let mut broker = SecretBroker::new();
    let secret_ref = broker
        .register("race-secret-1", b"secret-value".to_vec())
        .unwrap();
    let handle = broker.resolve(&secret_ref, true).unwrap();

    broker.revoke(&secret_ref).unwrap();

    assert_eq!(handle.value().unwrap(), b"secret-value");
    assert!(matches!(
        broker.resolve(&secret_ref, true),
        Err(SecretError::ReferenceRevoked)
    ));
}

#[tokio::test]
async fn race_secret_revoke_before_resolve() {
    let mut broker = SecretBroker::new();
    let secret_ref = broker
        .register("race-secret-2", b"secret-value".to_vec())
        .unwrap();

    broker.revoke(&secret_ref).unwrap();
    let result = broker.resolve(&secret_ref, true);

    assert!(matches!(result, Err(SecretError::ReferenceRevoked)));
}
