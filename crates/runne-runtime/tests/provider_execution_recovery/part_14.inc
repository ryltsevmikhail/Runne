#[tokio::test(flavor = "current_thread")]
async fn journal_key_unavailable_without_forward_binding_fails_closed() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let store = PausedAppendStore::unavailable(Arc::clone(&fixture.execution));
    let writer = runtime(&keyring, &store);
    let k1 = writer.preflight_existing_active_key([1; 16], 7).unwrap();
    let provider = SinglePollProvider {
        event: ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        polls: AtomicUsize::new(0),
    };

    assert_eq!(
        writer
            .next_and_commit(
                &provider,
                &ProviderStreamId::from_bytes([9; 16]),
                StreamCursor::new(0),
                &context(&fixture)
            )
            .await,
        Err(RuntimeProviderExecutionError::JournalCommitLost)
    );
    assert_eq!(
        store
            .attempts
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.key)
            .collect::<Vec<_>>(),
        vec![k1]
    );
    assert_eq!(provider.polls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.execution.active_journal_key_binding(), Ok(Some(k1)));
    assert_eq!(writer.recover_events(fixture.attempt_id), Ok(Vec::new()));
}
