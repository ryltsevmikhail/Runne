use gocode_application::provider::{ProviderExecutionError, ProviderExecutionStore};
use gocode_runtime::provider_execution::{
    ProviderTerminalOutboxApplication, RuntimeProviderExecution,
};
use gocode_store::provider::SqliteProviderExecutionStore;

use super::fixture::*;
use super::oracle::{assert_completed_receipt, assert_expected_terminal_recovery_delta};

#[tokio::test(flavor = "current_thread")]
async fn two_reconcilers_preloaded_before_ack_converge_to_single_receipt() {
    // The test uses ordered preload/application/ack calls and creates no threads or sleeps.
    let harness = Harness::new().await;
    let service = harness.compose().await;
    let (begin, started) = harness.begin();
    super::super::pending::create(&service, started.clone()).await;
    let before = snapshot(&harness.db_path);
    let keyring = harness.keyring();
    let prohibited = harness.prohibited();
    let store_a = SqliteProviderExecutionStore::open_with_connection(
        &harness.db_path,
        harness.open_runtime_connection(),
    )
    .unwrap();
    let store_b = SqliteProviderExecutionStore::open_with_connection(
        &harness.db_path,
        harness.open_runtime_connection(),
    )
    .unwrap();
    let runtime_a = RuntimeProviderExecution::new(
        keyring.as_ref(),
        &store_a,
        service.profile.as_ref(),
        prohibited.as_ref(),
    );
    let runtime_b = RuntimeProviderExecution::new(
        keyring.as_ref(),
        &store_b,
        service.profile.as_ref(),
        prohibited.as_ref(),
    );
    runtime_a
        .preflight_existing_active_key(service.runtime_authority_id, service.database_generation)
        .unwrap();
    runtime_b
        .preflight_existing_active_key(service.runtime_authority_id, service.database_generation)
        .unwrap();
    let pending_a = runtime_a.recover_pending_terminal_outputs().unwrap();
    let pending_b = runtime_b.recover_pending_terminal_outputs().unwrap();
    assert_eq!(pending_a.len(), 1);
    assert_eq!(pending_b.len(), 1);
    assert_eq!(pending_a[0].record(), pending_b[0].record());
    assert_eq!(pending_a[0].output(), pending_b[0].output());
    let application = harness.terminal_application();
    let receipt_a = application
        .complete_provider_terminal(pending_a[0].record(), pending_a[0].output())
        .unwrap();
    let receipt_b = application
        .complete_provider_terminal(pending_b[0].record(), pending_b[0].output())
        .unwrap();
    assert_ne!(receipt_a, [0; 32]);
    assert_eq!(receipt_b, receipt_a);
    store_a
        .acknowledge_terminal_outbox(pending_a[0].record().outbox_id, receipt_a)
        .unwrap();
    let after_first_ack = snapshot(&harness.db_path);
    store_b
        .acknowledge_terminal_outbox(pending_b[0].record().outbox_id, receipt_b)
        .unwrap();
    let after = snapshot(&harness.db_path);
    assert_eq!(after, after_first_ack);
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
    let before_conflict = snapshot(&harness.db_path);
    assert_eq!(
        store_b.acknowledge_terminal_outbox(pending_b[0].record().outbox_id, [9; 32]),
        Err(ProviderExecutionError::OutboxConflict)
    );
    assert_eq!(snapshot(&harness.db_path), before_conflict);
}
