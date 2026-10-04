#[tokio::test]
async fn queued_lifecycle_returns_one_exact_started_terminal_stream() {
    let profile = OpenAiResponsesTextProfile::from_json(PROFILE).unwrap();
    let server = start_create_server(true, true).await;
    let sink = Arc::new(IdentitySink {
        fail_request: false,
        fail_id: false,
        values: Mutex::new(Vec::new()),
        requests: Mutex::new(Vec::new()),
        barrier: None,
    });
    let (effect, outcome) =
        dispatch_create_with_effect(&server, &profile, sink.clone(), false).await;
    let stream = outcome.expect("valid queued stream has a factual terminal");
    assert_eq!(
        sink.values.lock().unwrap().as_slice(),
        ["resp_create_exact"]
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    let mut events = Vec::new();
    for sequence in 0..3 {
        let item = effect
            .next(&stream, StreamCursor::new(sequence))
            .await
            .unwrap();
        events.push(item.event().clone());
    }
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence())
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert!(matches!(
        events[0].kind(),
        runne_provider::ProviderStreamEventKind::Started
    ));
    assert!(matches!(
        events[1].kind(),
        runne_provider::ProviderStreamEventKind::UsageUnavailable
    ));
    assert!(matches!(
        events[2].kind(),
        runne_provider::ProviderStreamEventKind::Finished {
            disposition: runne_provider::ProviderTerminalDisposition::RemoteFailed,
            ..
        }
    ));
    server.task.await.unwrap();
}
