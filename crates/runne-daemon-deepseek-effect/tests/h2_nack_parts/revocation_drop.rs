struct PartialResponseServer {
    address: std::net::SocketAddr,
    certificate_der: Vec<u8>,
    first_chunk: tokio::sync::oneshot::Receiver<()>,
    reset: tokio::task::JoinHandle<Result<h2::Reason, ()>>,
}

impl PartialResponseServer {
    async fn start(authenticator: FixtureRequestAuthenticator) -> Self {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let (certificate_der, configuration) = tls_configuration();
        let (first_chunk_tx, first_chunk) = tokio::sync::oneshot::channel();
        let reset = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(|_| ())?;
            let tls = tokio_rustls::TlsAcceptor::from(configuration)
                .accept(tcp)
                .await
                .map_err(|_| ())?;
            let mut connection = h2::server::handshake(tls).await.map_err(|_| ())?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or(())?
                .map_err(|_| ())?;
            if request.method() != http::Method::POST
                || request.uri().path() != "/v1/responses"
                || !request
                    .headers()
                    .get(http::header::AUTHORIZATION)
                    .is_some_and(|value| authenticator.matches(value.as_bytes()))
            {
                return Err(());
            }
            let response = http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "text/event-stream")
                .body(())
                .map_err(|_| ())?;
            let mut body = respond.send_response(response, false).map_err(|_| ())?;
            body.send_data(bytes::Bytes::from_static(b"data: {\"type\":\"response."), false)
                .map_err(|_| ())?;
            first_chunk_tx.send(()).map_err(|_| ())?;
            loop {
                tokio::select! {
                    reason = std::future::poll_fn(|cx| body.poll_reset(cx)) => {
                        return reason.map_err(|_| ());
                    }
                    accepted = connection.accept() => {
                        if accepted.is_none() {
                            return Err(());
                        }
                    }
                }
            }
        });
        Self {
            address,
            certificate_der,
            first_chunk,
            reset,
        }
    }
}

#[tokio::test]
async fn dropping_authorized_effect_between_chunks_resets_real_http2_stream() {
    let profile = DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .expect("exact profile");
    let policy = DeepSeekTransportPolicy::for_profile(&profile).expect("transport policy");
    let authenticator = loopback_fixture_request_authenticator();
    let server = PartialResponseServer::start(authenticator).await;
    let client = loopback_fixture_client(&policy, server.address, &server.certificate_der)
        .expect("production-shaped loopback client");
    let (effect, _) = effect_from_loopback_fixture(client).expect("fixture effect");
    let (request, receipt, credential) = durable_dispatch(&profile, effect.as_ref());
    let ready = effect
        .stage_effect(request, credential)
        .await
        .expect("stage admitted effect");
    let dispatch_effect = Arc::clone(&effect);
    let task = tokio::spawn(async move { dispatch_effect.dispatch_effect(ready, receipt).await });

    tokio::time::timeout(Duration::from_secs(2), server.first_chunk)
        .await
        .expect("server emitted first chunk")
        .expect("first chunk signal");
    task.abort();
    assert!(task.await.expect_err("effect must be cancelled").is_cancelled());
    let reason = tokio::time::timeout(Duration::from_secs(2), server.reset)
        .await
        .expect("server must observe cancellation")
        .expect("server task")
        .expect("valid partial response");
    assert_eq!(reason, h2::Reason::CANCEL);
}
