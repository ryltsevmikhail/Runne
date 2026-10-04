#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_cancellation_during_credential_materialization_denies_final_send() {
    let profile = DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .expect("exact profile");
    let policy = DeepSeekTransportPolicy::for_profile(&profile).expect("transport policy");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let certificate = tls_configuration().0;
    let client = loopback_fixture_client(&policy, address, &certificate)
        .expect("production-shaped loopback client");
    let materializer = PausedLegacyCredentialMaterializer::fixture();
    let entered = materializer.entered.notified();
    tokio::pin!(entered);
    let effect = runne_daemon_deepseek_effect::effect_from_loopback_fixture_with_legacy_credential_materializer(
        client,
        materializer.clone(),
    )
    .expect("legacy-fixture materializer effect");
    let fixture = durable_dispatch(&profile, effect.as_ref());
    let cancellation = fixture.cancellation_target();
    let DurableDispatch {
        _runtime_root,
        request,
        receipt,
        credential,
        ..
    } = fixture;
    let ready = effect
        .stage_effect(request, credential)
        .await
        .expect("stage admitted effect");
    let dispatch = Arc::clone(&effect);
    let task = tokio::spawn(async move {
        let _runtime_root = _runtime_root;
        dispatch.dispatch_effect(ready, receipt).await
    });
    tokio::time::timeout(Duration::from_secs(5), &mut entered)
        .await
        .expect("legacy-fixture materialization barrier");

    cancellation.request_public_cancellation();
    materializer.release.add_permits(1);
    assert!(matches!(
        task.await.expect("sender task"),
        Err(DispatchError::RejectedBeforeEffect(_))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err()
    );
}
