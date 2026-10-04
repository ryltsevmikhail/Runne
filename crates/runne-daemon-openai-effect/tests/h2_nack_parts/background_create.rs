mod background_create_tests {
    use super::{loopback_fixture_client, tls_configuration};
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use runne_daemon_openai_effect::{OpenAiEffect, effect_from_loopback_background_fixture};
    use runne_domain::id::{AttemptId, TaskRunId};
    use runne_provider::{
        DispatchAttemptId, DispatchError, ProviderFuture, ProviderId,
        ProviderRecoveryAttemptIdentity, ProviderRecoveryBinding,
        ProviderRecoveryControlAuthorizer, ProviderRecoveryDispatchContext,
        ProviderRecoveryDispatchContextProvider, ProviderRecoveryError, ProviderRecoveryOperation,
        ProviderResponseIdentityCommitter, ProviderStreamId, RemoteResponseId, StreamCursor,
    };
    use runne_provider_openai::{
        OpenAiResponsesTextProfile, OpenAiResponsesTextRenderer, OpenAiTransportPolicy,
    };
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    const PROFILE: &[u8] =
        include_bytes!("../../../../docs/profiles/openai-responses-background-text-v1.json");

    struct NoControls;

    impl ProviderRecoveryControlAuthorizer for NoControls {
        fn authorize_and_materialize<'a>(
            &'a self,
            _: &'a runne_provider::ProviderRecoveryRequest,
            _: ProviderRecoveryOperation,
        ) -> ProviderFuture<
            'a,
            Result<runne_provider::ProviderRecoveryAuthorization, ProviderRecoveryError>,
        > {
            Box::pin(async { Err(ProviderRecoveryError::Unsupported) })
        }
    }

    struct IdentitySink {
        fail_request: bool,
        fail_id: bool,
        values: Mutex<Vec<String>>,
        requests: Mutex<Vec<Vec<u8>>>,
        barrier: Option<Arc<CreatePersistBarrier>>,
    }

    struct CreatePersistBarrier {
        entered: tokio::sync::Notify,
        release: tokio::sync::Semaphore,
    }

    impl CreatePersistBarrier {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Semaphore::new(0),
            })
        }
    }

    impl ProviderResponseIdentityCommitter for IdentitySink {
        fn persist_request<'a>(
            &'a self,
            _: ProviderRecoveryBinding,
            _: &'a ProviderRecoveryAttemptIdentity,
            request: &'a [u8],
        ) -> ProviderFuture<'a, Result<(), ProviderRecoveryError>> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request.to_vec());
                if let Some(barrier) = &self.barrier {
                    barrier.entered.notify_one();
                    barrier
                        .release
                        .acquire()
                        .await
                        .map_err(|_| ProviderRecoveryError::Unavailable)?
                        .forget();
                }
                if self.fail_request {
                    Err(ProviderRecoveryError::Unavailable)
                } else {
                    Ok(())
                }
            })
        }

        fn commit<'a>(
            &'a self,
            _: ProviderRecoveryBinding,
            response_id: &'a RemoteResponseId,
        ) -> ProviderFuture<'a, Result<(), ProviderRecoveryError>> {
            Box::pin(async move {
                self.values
                    .lock()
                    .unwrap()
                    .push(response_id.as_str().into());
                if self.fail_id {
                    Err(ProviderRecoveryError::Unavailable)
                } else {
                    Ok(())
                }
            })
        }
    }

    include!("background_create/contexts.rs");

    struct CreateServer {
        address: SocketAddr,
        certificate_der: Vec<u8>,
        requests: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    async fn start_create_server(expect_request: bool, valid_queue_terminal: bool) -> CreateServer {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (certificate_der, configuration) = tls_configuration();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let task = tokio::spawn(async move {
            let accepted = if expect_request {
                listener.accept().await.ok()
            } else {
                tokio::time::timeout(Duration::from_millis(250), listener.accept())
                    .await
                    .ok()
                    .and_then(Result::ok)
            };
            let Some((tcp, _)) = accepted else { return };
            let tls = TlsAcceptor::from(configuration).accept(tcp).await.unwrap();
            let mut connection = h2::server::handshake(tls).await.unwrap();
            let Some(Ok((request, mut respond))) = connection.accept().await else {
                return;
            };
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/v1/responses");
            assert_eq!(
                request.headers()[http::header::AUTHORIZATION],
                "Bearer fixture-credential"
            );
            assert!(request.headers().contains_key("x-client-request-id"));
            count.fetch_add(1, Ordering::SeqCst);
            let response = http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "text/event-stream")
                .body(())
                .unwrap();
            let mut body = respond.send_response(response, false).unwrap();
            if valid_queue_terminal {
                let frames = [
                    "event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_create_exact\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"background\":true,\"store\":false,\"status\":\"queued\",\"output\":[],\"usage\":null}}\n\n".to_owned(),
                    "event: response.queued\ndata: {\"type\":\"response.queued\",\"sequence_number\":1,\"response\":{\"id\":\"resp_create_exact\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"background\":true,\"store\":false,\"status\":\"queued\",\"output\":[],\"usage\":null}}\n\n".to_owned(),
                    "event: response.in_progress\ndata: {\"type\":\"response.in_progress\",\"sequence_number\":2,\"response\":{\"id\":\"resp_create_exact\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"background\":true,\"store\":false,\"status\":\"in_progress\",\"output\":[],\"usage\":null}}\n\n".to_owned(),
                    "event: response.failed\ndata: {\"type\":\"response.failed\",\"sequence_number\":3,\"response\":{\"id\":\"resp_create_exact\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"background\":true,\"store\":false,\"status\":\"failed\",\"output\":[],\"usage\":null,\"error\":{\"code\":\"server_error\",\"message\":\"safe\"}}}\n\n".to_owned(),
                ];
                for (sequence, frame) in frames.iter().enumerate() {
                    body.send_data(frame.clone().into(), sequence == frames.len() - 1)
                        .unwrap();
                }
            } else {
                let created = "event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_create_exact\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"background\":true,\"store\":false,\"status\":\"queued\",\"output\":[],\"usage\":null}}\n\n".to_owned();
                let later = "event: response.queued\ndata: {\"type\":\"response.queued\",\"sequence_number\":1,\"response\":{}}\n\n";
                body.send_data(created.into(), false).unwrap();
                body.send_data(later.into(), true).unwrap();
            }
            tokio::spawn(async move { while let Some(Ok(_)) = connection.accept().await {} });
        });
        CreateServer {
            address,
            certificate_der,
            requests,
            task,
        }
    }

    async fn dispatch_create(
        server: &CreateServer,
        profile: &OpenAiResponsesTextProfile,
        sink: Arc<IdentitySink>,
        wrong_attempt: bool,
    ) -> Result<(), DispatchError> {
        dispatch_create_with_effect(server, profile, sink, wrong_attempt)
            .await
            .1
            .map(|_| ())
    }

    async fn dispatch_create_with_effect(
        server: &CreateServer,
        profile: &OpenAiResponsesTextProfile,
        sink: Arc<IdentitySink>,
        wrong_attempt: bool,
    ) -> (
        Arc<dyn OpenAiEffect>,
        Result<ProviderStreamId, DispatchError>,
    ) {
        let (effect, fixture) = prepare_background_dispatch(server, profile, sink, wrong_attempt);
        assert!(fixture.receipt.matches_claim(fixture.request.claim()));
        assert!(fixture.receipt.matches_credential(&fixture.credential));
        assert_eq!(
            fixture.request.claim().profile_digest,
            profile.profile_digest()
        );
        assert_eq!(
            fixture.credential.version_ref().provider().as_str(),
            "openai-background"
        );
        let outcome = match effect
            .stage_effect(fixture.request, fixture.credential)
            .await
        {
            Ok(ready) => effect.dispatch_effect(ready, fixture.receipt).await,
            Err(error) => Err(error),
        };
        (effect, outcome)
    }

    fn prepare_background_dispatch(
        server: &CreateServer,
        profile: &OpenAiResponsesTextProfile,
        sink: Arc<IdentitySink>,
        wrong_attempt: bool,
    ) -> (Arc<dyn OpenAiEffect>, super::DurableDispatch) {
        let policy = OpenAiTransportPolicy::for_profile(profile).unwrap();
        let client =
            loopback_fixture_client(&policy, server.address, &server.certificate_der).unwrap();
        let prepared = OpenAiResponsesTextRenderer::new(profile.clone())
            .prepare(&super::openai_call(profile))
            .expect("exact background profile request");
        let fixture = super::durable_dispatch_with_prepared(profile, prepared);
        let contexts = Arc::new(Contexts {
            profile_digest: profile.profile_digest(),
            semantic_digest: fixture.semantic_digest,
            profile_id: profile.profile_id().to_owned(),
            pricing_digest: profile.pricing_revision_digest(),
            sink,
            wrong_attempt,
            taskrun_id: fixture.taskrun_id,
            task_attempt_id: fixture.task_attempt_id,
            authority_id: fixture.authority_id,
            database_generation: fixture.database_generation,
            runtime_generation: fixture.runtime_generation,
        });
        let effect =
            effect_from_loopback_background_fixture(client, contexts, Arc::new(NoControls))
                .unwrap();
        (effect, fixture)
    }

    #[tokio::test]
    async fn create_commits_validated_queued_id_before_later_event_and_sends_once() {
        let profile = OpenAiResponsesTextProfile::from_json(PROFILE).unwrap();
        let server = start_create_server(true, false).await;
        let sink = Arc::new(IdentitySink {
            fail_request: false,
            fail_id: false,
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
        assert_eq!(sink.requests.lock().unwrap().len(), 1);
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
        server.task.await.unwrap();
    }

    include!("background_create/queued_lifecycle.rs");
    include!("background_create/before_send.rs");
    include!("background_create/commit_after_send.rs");
    include!("background_create/cancel_before_send.rs");
}
