struct ConflictApplication(std::sync::atomic::AtomicUsize);

impl ProviderTerminalOutboxApplication for ConflictApplication {
    fn complete_provider_terminal(
        &self,
        _: &ProviderTerminalOutboxRecord,
        _: &[u8],
    ) -> Result<[u8; 32], ProviderTerminalApplicationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ProviderTerminalApplicationError::Conflict)
    }
}

struct CountingObserver(std::sync::atomic::AtomicUsize);

impl ProviderRecoveryObserver for CountingObserver {
    fn observe_recovered_terminal_output(&self) -> Result<(), ProviderRecoveryObserverError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_application_conflict_keeps_pending_outbox_without_mutation() {
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let writer = runtime(&keyring, fixture.execution.as_ref());
    writer.create_and_activate_key([1; 16], 7, 1).unwrap();
    poll_events(&writer, &fixture, successful_events("runtime-conflict")).await;
    writer.finalize_terminal_output(&context(&fixture)).unwrap();
    let before = validated_connection(&fixture);
    let snapshot = sql_snapshot(&before);
    assert_eq!(before.query_row("SELECT state FROM provider_dispatch_attempts", [], |r| r.get::<_, i64>(0)).unwrap(), 4);
    assert_eq!(before.query_row("SELECT state FROM provider_terminal_outbox", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
    drop(before);
    let application = ConflictApplication(std::sync::atomic::AtomicUsize::new(0));
    let observer = CountingObserver(std::sync::atomic::AtomicUsize::new(0));
    assert_eq!(writer.apply_pending_terminal_outputs(&application, &observer), Err(RuntimeProviderExecutionError::ApplicationConflict));
    assert_eq!(application.0.load(Ordering::SeqCst), 1);
    assert_eq!(observer.0.load(Ordering::SeqCst), 0);
    assert_eq!(sql_snapshot(&validated_connection(&fixture)), snapshot);
}
