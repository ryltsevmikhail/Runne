#[path = "task5_support.rs"]
mod task5_support;
#[path = "task5_fixture.rs"]
mod task5_fixture;

#[tokio::test(flavor = "current_thread")]
async fn terminal_scanner_failure_has_no_publication() {
    use gocode_provider::{
        ProviderRepositoryState, ScannerTerminalDisposition, ScannerUncertainReason, StreamCursor,
    };
    use gocode_runtime::provider_execution::{
        RuntimeProviderExecution, RuntimeProviderExecutionError,
    };
    use gocode_runtime::provider_redaction::{
        ProviderEventRedactionBoundary, ScannerRecoveryPersistence,
    };
    use gocode_store::provider::SqliteProviderRecoveryStore;

    use task5_fixture::Task5ProductionFixture;
    use task5_support::*;

    let fixture = Task5ProductionFixture::new();
    let recovery = SqliteProviderRecoveryStore::open(fixture.path(), [1; 16]).unwrap();
    let tails = SecretTailStore::default();
    let redaction =
        ProviderEventRedactionBoundary::new(&tails, &recovery, &SecretMatcher);
    let keyring = MemoryKeyring::default();
    let runtime = RuntimeProviderExecution::new(
        &keyring,
        fixture.execution(),
        &FixedPricing,
        &AllowingGuard,
        &redaction,
    );
    runtime.create_and_activate_key([1; 16], 7, 1).unwrap();
    let provider = SecretProvider::default();

    runtime
        .next_and_commit(
            &provider,
            fixture.stream(),
            StreamCursor::new(0),
            fixture.context(),
        )
        .await
        .unwrap();
    assert_eq!(
        runtime
            .next_and_commit(
                &provider,
                fixture.stream(),
                StreamCursor::new(1),
                fixture.context(),
            )
            .await,
        Err(RuntimeProviderExecutionError::PolicyDenied)
    );
    assert_eq!(
        runtime
            .next_and_commit(
                &provider,
                fixture.stream(),
                StreamCursor::new(1),
                fixture.context(),
            )
            .await,
        Err(RuntimeProviderExecutionError::RecoveryFrozen)
    );

    assert_eq!(provider.polls(), 2, "frozen retry repolled the adapter");
    assert_eq!(
        recovery
            .load(fixture.attempt())
            .unwrap()
            .unwrap()
            .disposition(),
        Some(ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::SecretDetected,
        ))
    );
    assert_eq!(
        runtime.finalize_terminal_output(fixture.context()),
        Err(RuntimeProviderExecutionError::PolicyDenied)
    );
    let replay = runtime.recover_events(fixture.attempt()).unwrap();
    assert_eq!(replay.len(), 1);
    assert!(matches!(
        replay[0].kind(),
        gocode_provider::ProviderStreamEventKind::Started
    ));
    assert_eq!(fixture.persisted_counts(), (1, 0, 0, 1));
    assert_eq!(fixture.dispatch_state(), ProviderRepositoryState::Uncertain);
    assert_eq!(
        fixture.retry_idempotency_state(),
        ProviderRepositoryState::Uncertain
    );
    assert_eq!(recovery.canonical_publication_counts().unwrap(), (0, 0));
    assert_eq!(tails.tail_count(), 0);
    fixture.assert_secret_absent_from_durable_files();
}
