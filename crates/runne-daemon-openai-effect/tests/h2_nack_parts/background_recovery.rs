mod background_recovery_tests {
    use super::{loopback_fixture_client, tls_configuration};
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use runne_daemon_openai_effect::{
        OpenAiEffect, effect_from_loopback_background_fixture,
        effect_from_loopback_background_fixture_with_timeout,
    };
    use runne_domain::id::{AttemptId, TaskRunId};
    use runne_provider::{
        DispatchAttemptId, ProviderFuture, ProviderRecoveryAuthorization, ProviderRecoveryBinding,
        ProviderRecoveryControlAuthorizer, ProviderRecoveryDispatchContext,
        ProviderRecoveryDispatchContextProvider, ProviderRecoveryError, ProviderRecoveryOperation,
        ProviderRecoveryRequest, ProviderRemoteResponseStatus, RemoteResponseId,
    };
    use runne_provider_openai::{OpenAiResponsesTextProfile, OpenAiTransportPolicy};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use zeroize::Zeroizing;

    const BACKGROUND_PROFILE: &[u8] =
        include_bytes!("../../../../docs/profiles/openai-responses-background-text-v1.json");
    const PENDING: &[u8] = br#"{"id":"resp_exact","object":"response","model":"gpt-5.5-2026-04-23","service_tier":"default","background":true,"store":false,"status":"queued","output":[],"usage":null}"#;
    const COMPLETED: &[u8] = br#"{"id":"resp_exact","object":"response","model":"gpt-5.5-2026-04-23","service_tier":"default","background":true,"store":false,"status":"completed","output":[{"id":"msg_1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","annotations":[],"text":"done"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}},"error":null,"incomplete_details":null}"#;

    struct NoDispatchContext;

    impl ProviderRecoveryDispatchContextProvider for NoDispatchContext {
        fn for_dispatch<'a>(
            &'a self,
            _: &'a runne_provider::ProviderDispatchClaim,
        ) -> ProviderFuture<'a, Result<ProviderRecoveryDispatchContext, ProviderRecoveryError>>
        {
            Box::pin(async { Err(ProviderRecoveryError::Unavailable) })
        }
    }

    struct RecoveryAuth {
        calls: AtomicUsize,
    }

    impl ProviderRecoveryControlAuthorizer for RecoveryAuth {
        fn authorize_and_materialize<'a>(
            &'a self,
            request: &'a ProviderRecoveryRequest,
            operation: ProviderRecoveryOperation,
        ) -> ProviderFuture<'a, Result<ProviderRecoveryAuthorization, ProviderRecoveryError>>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let proof = runne_provider::ProviderRemoteOperationProof::new(
                request.binding(),
                operation,
                request.response_id(),
                [91; 16],
                u64::MAX,
            );
            Box::pin(async move {
                let proof = proof?;
                ProviderRecoveryAuthorization::new(
                    Zeroizing::new(b"control-fixture".to_vec()),
                    proof,
                )
            })
        }
    }

    struct ControlServer {
        address: SocketAddr,
        certificate_der: Vec<u8>,
        task: tokio::task::JoinHandle<()>,
    }

    async fn start_server(
        method: &'static str,
        path: &'static str,
        status: u16,
        body: &'static [u8],
    ) -> ControlServer {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (certificate_der, configuration) = tls_configuration();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(configuration).accept(tcp).await.unwrap();
            let mut connection = h2::server::handshake(tls).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method().as_str(), method);
            assert_eq!(request.uri().path(), path);
            assert_eq!(
                request.headers()[http::header::AUTHORIZATION],
                "Bearer control-fixture"
            );
            let response = http::Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(())
                .unwrap();
            let mut stream = respond.send_response(response, body.is_empty()).unwrap();
            if !body.is_empty() {
                stream.send_data(body.into(), true).unwrap();
            }
            tokio::spawn(async move { while let Some(Ok(_)) = connection.accept().await {} });
        });
        ControlServer {
            address,
            certificate_der,
            task,
        }
    }

    async fn start_delayed_server(
        method: &'static str,
        path: &'static str,
        delay_headers: bool,
    ) -> ControlServer {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (certificate_der, configuration) = tls_configuration();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(configuration).accept(tcp).await.unwrap();
            let mut connection = h2::server::handshake(tls).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method().as_str(), method);
            assert_eq!(request.uri().path(), path);
            if delay_headers {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let response = http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(())
                .unwrap();
            let mut stream = respond.send_response(response, false).unwrap();
            if !delay_headers {
                stream.send_data(b"{".to_vec().into(), false).unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let _ = stream.send_data(b"}".to_vec().into(), true);
            tokio::spawn(async move { while let Some(Ok(_)) = connection.accept().await {} });
        });
        ControlServer {
            address,
            certificate_der,
            task,
        }
    }

    fn background_effect<A: ProviderRecoveryControlAuthorizer + 'static>(
        server: &ControlServer,
        auth: Arc<A>,
    ) -> Arc<dyn OpenAiEffect> {
        let profile = OpenAiResponsesTextProfile::from_json(BACKGROUND_PROFILE).unwrap();
        let policy = OpenAiTransportPolicy::for_profile(&profile).unwrap();
        let client =
            loopback_fixture_client(&policy, server.address, &server.certificate_der).unwrap();
        effect_from_loopback_background_fixture(client, Arc::new(NoDispatchContext), auth).unwrap()
    }

    fn short_deadline_effect<A: ProviderRecoveryControlAuthorizer + 'static>(
        server: &ControlServer,
        auth: Arc<A>,
    ) -> Arc<dyn OpenAiEffect> {
        let profile = OpenAiResponsesTextProfile::from_json(BACKGROUND_PROFILE).unwrap();
        let policy = OpenAiTransportPolicy::for_profile(&profile).unwrap();
        let client =
            loopback_fixture_client(&policy, server.address, &server.certificate_der).unwrap();
        effect_from_loopback_background_fixture_with_timeout(
            client,
            Arc::new(NoDispatchContext),
            auth,
            std::time::Duration::from_millis(20),
        )
        .unwrap()
    }

    fn request(profile: &OpenAiResponsesTextProfile) -> ProviderRecoveryRequest {
        let binding = ProviderRecoveryBinding::new(
            TaskRunId::from_bytes([4; 16]),
            AttemptId::from_bytes([5; 16]),
            DispatchAttemptId::from_bytes([6; 16]),
            profile.profile_digest(),
        )
        .unwrap();
        ProviderRecoveryRequest::new(binding, RemoteResponseId::new("resp_exact").unwrap())
    }

    #[tokio::test]
    async fn status_get_uses_exact_response_id_and_pending_is_not_terminal() {
        let profile = OpenAiResponsesTextProfile::from_json(BACKGROUND_PROFILE).unwrap();
        let server = start_server("GET", "/v1/responses/resp_exact", 200, PENDING).await;
        let auth = Arc::new(RecoveryAuth {
            calls: AtomicUsize::new(0),
        });
        let effect = background_effect(&server, auth.clone());
        assert!(effect.recovery_capabilities().status_check);
        assert!(!effect.recovery_capabilities().stream_resume);
        assert!(effect.recovery_capabilities().remote_cancel);
        let check = effect.check_remote_status(request(&profile)).await.unwrap();
        assert_eq!(check.status(), &ProviderRemoteResponseStatus::Pending);
        assert!(check.terminal().is_none());
        assert_eq!(auth.calls.load(Ordering::SeqCst), 1);
        server.task.await.unwrap();
    }

    #[tokio::test]
    async fn cancel_post_preserves_racing_completed_outcome_and_text() {
        let profile = OpenAiResponsesTextProfile::from_json(BACKGROUND_PROFILE).unwrap();
        let server = start_server("POST", "/v1/responses/resp_exact/cancel", 200, COMPLETED).await;
        let auth = Arc::new(RecoveryAuth {
            calls: AtomicUsize::new(0),
        });
        let effect = background_effect(&server, auth.clone());
        let check = effect.cancel_remote(request(&profile)).await.unwrap();
        assert!(matches!(
            check.status(),
            ProviderRemoteResponseStatus::Completed { usage: Some(_) }
        ));
        assert_eq!(check.terminal().unwrap().output_text(), Some("done"));
        assert_eq!(auth.calls.load(Ordering::SeqCst), 1);
        server.task.await.unwrap();
    }

    #[tokio::test]
    async fn recovery_deadline_covers_stalled_headers_and_slow_body() {
        let profile = OpenAiResponsesTextProfile::from_json(BACKGROUND_PROFILE).unwrap();
        for delay_headers in [true, false] {
            let server =
                start_delayed_server("GET", "/v1/responses/resp_exact", delay_headers).await;
            let auth = Arc::new(RecoveryAuth {
                calls: AtomicUsize::new(0),
            });
            let effect = short_deadline_effect(&server, auth.clone());
            assert!(matches!(
                effect.check_remote_status(request(&profile)).await,
                Err(runne_provider::ProviderRecoveryError::Unavailable)
            ));
            assert_eq!(auth.calls.load(Ordering::SeqCst), 1);
            server.task.abort();
            let _ = server.task.await;
        }
    }

    include!("background_recovery_negative.rs");
}
