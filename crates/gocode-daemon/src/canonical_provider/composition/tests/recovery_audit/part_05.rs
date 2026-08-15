use gocode_provider::{ScannerTerminalDisposition, ScannerUncertainReason};
use gocode_runtime::provider_redaction::ScannerRecoveryPersistence;

use super::fixture::*;

#[tokio::test(flavor = "current_thread")]
async fn restart_does_not_decrypt_or_apply_outbox_without_scanner_completed() {
    let harness = Harness::new().await;
    let service = harness.compose().await;
    let (_begin, started) = harness.begin();
    let attempt = super::super::pending::create(&service, started).await;
    let record = service.scanner_store.load(attempt).unwrap().unwrap();
    assert_eq!(
        service
            .scanner_store
            .commit_terminal(
                record.binding(),
                ScannerTerminalDisposition::Uncertain(ScannerUncertainReason::SecretDetected),
            )
            .unwrap(),
        ScannerTerminalDisposition::Uncertain(ScannerUncertainReason::SecretDetected)
    );
    let before = snapshot(&harness);
    drop(service);

    assert!(
        harness
            .try_compose_at_generation(harness.generation())
            .await
            .is_err()
    );
    let after = snapshot(&harness);
    assert_unchanged_except(&before, &after, &["provider_runtime_authority_state"]);
    let connection = harness.query_connection();
    assert_eq!(
        connection
            .query_row("SELECT state FROM provider_terminal_outbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT state FROM provider_dispatch_attempts", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        4
    );
}
