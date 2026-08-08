use super::fixture::*;
use super::oracle::{
    assert_authority_renewal, assert_completed_receipt, assert_expected_terminal_recovery_delta,
};

#[tokio::test(flavor = "current_thread")]
async fn recompose_without_pending_outbox_changes_only_authority_renewal() {
    let harness = Harness::new().await;
    let service = harness.compose().await;
    let before = snapshot(&harness.db_path);
    drop(service);
    let service = harness.compose_at_generation(harness.generation()).await;
    let after = snapshot(&harness.db_path);
    assert_unchanged_except(&before, &after, &["provider_runtime_authority_state"]);
    assert_authority_renewal(&before, &after, &harness.db_path, harness.generation());
    assert!(service.recover_pending().await.is_ok());
    assert_eq!(snapshot(&harness.db_path), after);
}

#[tokio::test(flavor = "current_thread")]
async fn reopen_with_pending_outbox_changes_only_lifecycle_columns() {
    let harness = Harness::new().await;
    let service = harness.compose().await;
    let (begin, started) = harness.begin();
    super::super::pending::create(&service, started.clone()).await;
    let before = snapshot(&harness.db_path);
    service.recover_pending().await.unwrap();
    let after = snapshot(&harness.db_path);
    assert_expected_terminal_recovery_delta(
        &before,
        &after,
        &harness.db_path,
        begin.command_id,
        &started,
        false,
    );
    let receipt = harness
        .store
        .load_text_generation_receipt_by_command(begin.command_id, &begin.idempotency_key)
        .unwrap();
    assert_completed_receipt(&receipt, &started);
}
