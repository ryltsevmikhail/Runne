use super::fixture::*;
use super::oracle::{
    assert_authority_renewal, assert_completed_receipt, assert_expected_terminal_recovery_delta,
};

#[tokio::test(flavor = "current_thread")]
async fn recompose_without_pending_outbox_changes_only_authority_renewal() {
    let harness = Harness::new().await;
    let service = harness.compose().await;
    let before = snapshot(&harness);
    drop(service);
    let service = harness.compose_at_generation(harness.generation()).await;
    let after = snapshot(&harness);
    assert_unchanged_except(&before, &after, &["provider_runtime_authority_state"]);
    assert_authority_renewal(&before, &after, &harness, harness.generation());
    assert!(service.recover_pending().await.is_ok());
    assert_eq!(snapshot(&harness), after);
}

#[tokio::test(flavor = "current_thread")]
async fn reopen_with_pending_outbox_changes_only_lifecycle_columns() {
    let harness = Harness::new().await;
    let service = harness.compose().await;
    let (begin, started) = harness.begin();
    super::super::pending::create(&service, started.clone(), harness.writer_connection()).await;
    let before = snapshot(&harness);
    service.recover_pending().await.unwrap();
    let after = snapshot(&harness);
    assert_expected_terminal_recovery_delta(
        &before,
        &after,
        &harness,
        begin.command_id,
        &started,
        false,
        false,
    );
    let receipt = harness
        .store
        .load_text_generation_receipt_by_command(begin.command_id, &begin.idempotency_key)
        .unwrap();
    assert_completed_receipt(&receipt, &started);
}

#[tokio::test(flavor = "current_thread")]
async fn live_service_renews_expired_launch_and_keeps_lease_stable_through_settlement() {
    let harness = Harness::new().await;
    let service = harness.compose().await;
    let (_, started) = harness.begin();
    rusqlite::Connection::open(&harness.db_path)
        .unwrap()
        .execute(
            "UPDATE provider_runtime_authority_state
             SET capability_expires_at = 1, approval_expires_at = 1 WHERE id = 1",
            [],
        )
        .unwrap();

    let _dispatch_guard = service.acquire_dispatch_gate().await;
    service.renew_launch_authority().unwrap();
    let expiry = rusqlite::Connection::open(&harness.db_path)
        .unwrap()
        .query_row(
            "SELECT capability_expires_at FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert!(expiry > 1);

    super::super::pending::create(&service, started, harness.writer_connection()).await;
    let queued_service = std::sync::Arc::clone(&service);
    let (entered_tx, mut entered_rx) = tokio::sync::oneshot::channel();
    let queued = tokio::spawn(async move {
        let _guard = queued_service.acquire_dispatch_gate().await;
        let _ = entered_tx.send(());
        queued_service.renew_launch_authority().unwrap();
    });
    tokio::task::yield_now().await;
    assert!(matches!(
        entered_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    service.recover_pending().await.unwrap();
    let settled_state = rusqlite::Connection::open(&harness.db_path)
        .unwrap()
        .query_row(
            "SELECT dispatch.state, runtime.capability_expires_at
             FROM provider_dispatch_attempts dispatch
             JOIN provider_runtime_authority_state runtime ON runtime.id = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap();
    assert_eq!(settled_state, (5, expiry));
    drop(_dispatch_guard);
    entered_rx.await.unwrap();
    queued.await.unwrap();
}
