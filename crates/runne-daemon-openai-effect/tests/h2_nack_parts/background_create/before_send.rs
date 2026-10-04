#[tokio::test]
async fn request_persistence_failure_is_known_pre_send_and_sends_nothing() {
    let profile = OpenAiResponsesTextProfile::from_json(PROFILE).unwrap();
    let server = start_create_server(true, false).await;
    let sink = Arc::new(IdentitySink {
        fail_request: true,
        fail_id: false,
        values: Mutex::new(Vec::new()),
        requests: Mutex::new(Vec::new()),
        barrier: None,
    });
    let outcome = dispatch_create(&server, &profile, sink.clone(), false).await;
    assert_eq!(
        outcome,
        Err(DispatchError::RejectedBeforeEffect(
            runne_provider::ProviderPreEffectRejection::ProfileRejected
        ))
    );
    // The persisted-request committer is invoked and fails before transport POST;
    // this sender classifies that recovery-context failure as ProfileRejected.
    assert_eq!(sink.requests.lock().unwrap().len(), 1);
    assert!(sink.values.lock().unwrap().is_empty());
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
    server.task.abort();
}
