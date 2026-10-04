#[tokio::test]
async fn failed_identity_commit_is_uncertain_after_send_and_wrong_context_is_pre_send() {
    let profile = OpenAiResponsesTextProfile::from_json(PROFILE).unwrap();
    let server = start_create_server(true, false).await;
    let sink = Arc::new(IdentitySink {
        fail_request: false,
        fail_id: true,
        values: Mutex::new(Vec::new()),
        requests: Mutex::new(Vec::new()),
        barrier: None,
    });
    assert_eq!(
        dispatch_create(&server, &profile, sink.clone(), false).await,
        Err(DispatchError::MaybeDispatched)
    );
    assert_eq!(
        sink.values.lock().unwrap().as_slice(),
        ["resp_create_exact"]
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    server.task.await.unwrap();

    let server = start_create_server(false, false).await;
    let sink = Arc::new(IdentitySink {
        fail_request: false,
        fail_id: false,
        values: Mutex::new(Vec::new()),
        requests: Mutex::new(Vec::new()),
        barrier: None,
    });
    assert_eq!(
        dispatch_create(&server, &profile, sink.clone(), true).await,
        Err(DispatchError::RejectedBeforeEffect(
            runne_provider::ProviderPreEffectRejection::ProfileRejected
        ))
    );
    assert!(sink.values.lock().unwrap().is_empty());
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
    server.task.await.unwrap();
}
