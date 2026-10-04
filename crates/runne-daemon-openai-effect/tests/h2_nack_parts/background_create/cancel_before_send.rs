#[tokio::test]
async fn public_cancellation_during_background_context_persistence_prevents_post() {
    let profile = OpenAiResponsesTextProfile::from_json(PROFILE).unwrap();
    let server = start_create_server(false, false).await;
    let barrier = CreatePersistBarrier::new();
    let sink = Arc::new(IdentitySink {
        fail_request: false,
        fail_id: false,
        values: Mutex::new(Vec::new()),
        requests: Mutex::new(Vec::new()),
        barrier: Some(Arc::clone(&barrier)),
    });
    let (effect, fixture) = prepare_background_dispatch(&server, &profile, sink.clone(), false);
    let database_path = fixture.database_path.clone();
    let database_identity = fixture.database_identity;
    let runtime_authority = fixture.runtime_authority.clone();
    let taskrun_id = fixture.taskrun_id;
    let request = fixture.request;
    let credential = fixture.credential;
    let receipt = fixture.receipt;
    let entered = barrier.entered.notified();
    tokio::pin!(entered);
    let dispatch = tokio::spawn(async move {
        match effect.stage_effect(request, credential).await {
            Ok(ready) => effect.dispatch_effect(ready, receipt).await,
            Err(error) => Err(error),
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), &mut entered)
        .await
        .expect("background adapter reached persisted-request pre-send barrier");
    super::cancel_task_run_publicly(
        &database_path,
        database_identity,
        runtime_authority,
        taskrun_id,
    );
    barrier.release.add_permits(1);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), dispatch)
            .await
            .expect("background dispatch completes after cancellation")
            .unwrap(),
        Err(DispatchError::RejectedBeforeEffect(
            runne_provider::ProviderPreEffectRejection::AdapterRejected
        )),
        "cancelled final-send authority must reject at the consume boundary"
    );
    assert_eq!(sink.requests.lock().unwrap().len(), 1);
    assert!(sink.values.lock().unwrap().is_empty());
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
    server.task.await.unwrap();
}
