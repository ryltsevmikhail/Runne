use super::cancellation_support::{pending_terminal_snapshot_on, request_public_cancellation};
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn corrupt_cancellation_successor_does_not_defer_terminal_outbox() {
    let scenario = setup::prepare_failure_scenario().await;
    request_public_cancellation(&scenario);
    assert!(!terminal_success::seal_success_and_try_foreground(&scenario).await);
    let PreparedFailureScenario {
        harness,
        service,
        taskrun_id,
        ..
    } = scenario;
    let outbox_reader = harness.query_connection();
    drop(service);
    harness
        .writer_connection()
        .execute(
            "UPDATE events SET payload=?1 WHERE aggregate_type=1 AND aggregate_id=?2 AND sequence=5",
            rusqlite::params![vec![0_u8], taskrun_id.as_bytes()],
        )
        .unwrap();

    assert!(
        harness
            .try_compose_openai_provider_at_generation(harness.generation())
            .await
            .is_err()
    );
    assert_eq!(pending_terminal_snapshot_on(&outbox_reader).state, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn mismatched_started_receipt_fingerprint_does_not_defer_outbox() {
    let scenario = setup::prepare_failure_scenario().await;
    request_public_cancellation(&scenario);
    assert!(!terminal_success::seal_success_and_try_foreground(&scenario).await);
    let PreparedFailureScenario {
        harness,
        service,
        begin_context,
        ..
    } = scenario;
    let outbox_reader = harness.query_connection();
    drop(service);
    harness
        .writer_connection()
        .execute(
            "UPDATE command_receipts SET fingerprint=zeroblob(32)
             WHERE command_id=?1 AND idempotency_key=?2",
            rusqlite::params![
                begin_context.command_id.as_bytes(),
                begin_context.idempotency_key.as_str().as_bytes()
            ],
        )
        .unwrap();

    assert!(
        harness
            .try_compose_openai_provider_at_generation(harness.generation())
            .await
            .is_err()
    );
    assert_eq!(pending_terminal_snapshot_on(&outbox_reader).state, 1);
}
