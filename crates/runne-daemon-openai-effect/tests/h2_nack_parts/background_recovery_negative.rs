struct DeniedAuth {
    calls: AtomicUsize,
}

impl ProviderRecoveryControlAuthorizer for DeniedAuth {
    fn authorize_and_materialize<'a>(
        &'a self,
        _: &'a ProviderRecoveryRequest,
        _: ProviderRecoveryOperation,
    ) -> ProviderFuture<
        'a,
        Result<runne_provider::ProviderRecoveryAuthorization, ProviderRecoveryError>,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(ProviderRecoveryError::Unavailable) })
    }
}

async fn start_idle_server() -> (SocketAddr, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepted = accepts.clone();
    let task = tokio::spawn(async move {
        if tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
            .await
            .is_ok()
        {
            accepted.fetch_add(1, Ordering::SeqCst);
        }
    });
    (address, task, accepts)
}

#[tokio::test]
async fn missing_auth_and_bad_status_observations_never_fabricate_terminal_evidence() {
    let profile = OpenAiResponsesTextProfile::from_json(BACKGROUND_PROFILE).unwrap();
    let auth = Arc::new(RecoveryAuth {
        calls: AtomicUsize::new(0),
    });
    let server = start_server("GET", "/v1/responses/resp_exact", 404, b"").await;
    let check = background_effect(&server, auth.clone())
        .check_remote_status(request(&profile))
        .await
        .unwrap();
    assert_eq!(check.status(), &ProviderRemoteResponseStatus::Unknown);
    assert!(check.terminal().is_none());
    server.task.await.unwrap();

    let server = start_server("GET", "/v1/responses/resp_exact", 401, b"{}").await;
    assert!(matches!(
        background_effect(&server, auth.clone())
            .check_remote_status(request(&profile))
            .await,
        Err(ProviderRecoveryError::Unavailable)
    ));
    server.task.await.unwrap();

    let invalid_responses: [&[u8]; 3] = [
            br#"{"id":"resp_other","object":"response","model":"gpt-5.5-2026-04-23","service_tier":"default","background":true,"store":false,"status":"queued","output":[],"usage":null}"#,
            br#"{"id":"resp_exact","object":"response","model":"wrong-model","service_tier":"default","background":true,"store":false,"status":"queued","output":[],"usage":null}"#,
            b"{",
        ];
    for body in invalid_responses {
        let server = start_server("GET", "/v1/responses/resp_exact", 200, body).await;
        assert!(matches!(
            background_effect(&server, auth.clone())
                .check_remote_status(request(&profile))
                .await,
            Err(ProviderRecoveryError::InvalidIdentity)
        ));
        server.task.await.unwrap();
    }

    let (address, task, accepts) = start_idle_server().await;
    let policy = OpenAiTransportPolicy::for_profile(&profile).unwrap();
    let client = loopback_fixture_client(&policy, address, &tls_configuration().0).unwrap();
    let denied = Arc::new(DeniedAuth {
        calls: AtomicUsize::new(0),
    });
    let effect = effect_from_loopback_background_fixture(
        client,
        Arc::new(NoDispatchContext),
        denied.clone(),
    )
    .unwrap();
    assert!(matches!(
        effect.check_remote_status(request(&profile)).await,
        Err(ProviderRecoveryError::Unavailable)
    ));
    task.await.unwrap();
    assert_eq!(denied.calls.load(Ordering::SeqCst), 1);
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
}
