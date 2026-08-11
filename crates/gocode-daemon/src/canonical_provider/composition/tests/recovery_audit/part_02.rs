use super::fixture::*;
use super::oracle::{
    assert_authority_renewal, assert_completed_receipt, assert_expected_terminal_recovery_delta,
};

#[tokio::test(flavor = "current_thread")]
async fn duplicate_outbox_wakeup_second_recovery_applies_zero() {
    let harness = Harness::new().await;
    let service = harness.compose().await;
    let (begin, started) = harness.begin();
    super::super::pending::create(&service, started.clone()).await;
    let registry = service.recovery_observation_registry();
    let before = registry.snapshot_recovery_observation();
    service.recover_pending().await.unwrap();
    let first = registry.snapshot_recovery_observation();
    assert_eq!(
        first.observed_count(),
        Some(before.observed_count().unwrap() + 1)
    );
    let snapshot_after_first = snapshot(&harness.db_path);
    service.recover_pending().await.unwrap();
    let second = registry.snapshot_recovery_observation();
    assert!(second.availability() == first.availability());
    assert_eq!(second.observed_count(), first.observed_count());
    assert_eq!(second.dropped_event_count(), first.dropped_event_count());
    assert_eq!(
        second.drop_counter_saturated(),
        first.drop_counter_saturated()
    );
    assert_eq!(snapshot(&harness.db_path), snapshot_after_first);
    let receipt = harness
        .store
        .load_text_generation_receipt_by_command(begin.command_id, &begin.idempotency_key)
        .unwrap();
    assert_completed_receipt(&receipt, &started);
}

#[tokio::test(flavor = "current_thread")]
async fn recovery_completes_before_compose_returns() {
    let harness = Harness::new().await;
    let first = harness.compose().await;
    let (begin, started) = harness.begin();
    super::super::pending::create(&first, started.clone()).await;
    let before = snapshot(&harness.db_path);
    drop(first);

    let composed = harness.compose().await;
    let after = snapshot(&harness.db_path);
    assert_expected_terminal_recovery_delta(
        &before,
        &after,
        &harness.db_path,
        begin.command_id,
        &started,
        true,
        false,
    );
    assert_authority_renewal(&before, &after, &harness.db_path, harness.generation());
    assert_eq!(
        rusqlite::Connection::open(&harness.db_path)
            .unwrap()
            .query_row("SELECT state FROM provider_terminal_outbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        2
    );
    assert_eq!(
        rusqlite::Connection::open(&harness.db_path)
            .unwrap()
            .query_row("SELECT state FROM provider_dispatch_attempts", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        5
    );
    let receipt = harness
        .store
        .load_text_generation_receipt_by_command(begin.command_id, &begin.idempotency_key)
        .unwrap();
    assert_completed_receipt(&receipt, &started);
    assert_eq!(
        composed
            .recovery_observation_registry()
            .snapshot_recovery_observation()
            .observed_count(),
        Some(1)
    );
}
