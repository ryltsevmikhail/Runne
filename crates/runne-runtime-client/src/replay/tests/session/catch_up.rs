    #[test]
    fn stable_persistence_binding_excludes_ephemeral_session_identity() {
        let first = test_client("127.0.0.1:9".parse().unwrap());
        let mut second_session = first.session_info().clone();
        second_session.daemon_instance_id = "another-instance".to_owned();
        second_session.launch_generation = 99;
        second_session.session_id = "another-session".to_owned();
        second_session.authorization_epoch = 42;
        second_session.certificate_sha256 = "another-certificate".to_owned();
        let second = AuthenticatedRuntimeClient::from_local_session(
            reqwest::Client::new(),
            "http://127.0.0.1:9".to_owned(),
            crate::RuntimeSessionAuthority::from_local_session([8; 32]),
            second_session,
            Vec::new(),
        );

        assert_eq!(
            first.replay_persistence_binding().digest(),
            second.replay_persistence_binding().digest()
        );
        assert_eq!(first.replay_persistence_binding().digest().len(), 64);

        for mutate in [
            |session: &mut crate::RuntimeSessionInfo| {
                session.authority_id = "another-authority".to_owned();
            },
            |session: &mut crate::RuntimeSessionInfo| {
                session.principal_id = "another-principal".to_owned();
            },
            |session: &mut crate::RuntimeSessionInfo| {
                session.event_log_lineage_id = "another-lineage".to_owned();
            },
            |session: &mut crate::RuntimeSessionInfo| {
                session.profile_id = "another-profile".to_owned();
            },
            |session: &mut crate::RuntimeSessionInfo| {
                session.schema_hash = "another-schema".to_owned();
            },
            |session: &mut crate::RuntimeSessionInfo| {
                session.capability_digest = "another-capabilities".to_owned();
            },
        ] {
            let mut changed_session = first.session_info().clone();
            mutate(&mut changed_session);
            let changed = AuthenticatedRuntimeClient::from_local_session(
                reqwest::Client::new(),
                "http://127.0.0.1:9".to_owned(),
                crate::RuntimeSessionAuthority::from_local_session([9; 32]),
                changed_session,
                Vec::new(),
            );
            assert_ne!(
                first.replay_persistence_binding().digest(),
                changed.replay_persistence_binding().digest()
            );
        }
    }

    #[tokio::test]
    async fn catch_up_applies_before_each_ack_then_enters_live() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let acknowledged_count = Arc::new(AtomicUsize::new(0));
        let server_acknowledged_count = Arc::clone(&acknowledged_count);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let expected = [
                "/v1/replay/open-session",
                "/v1/replay/018f2e3a700070008000000000000118/acknowledge",
                "/v1/replay/018f2e3a700070008000000000000118/read-page",
                "/v1/replay/018f2e3a700070008000000000000118/acknowledge",
                "/v1/replay/018f2e3a700070008000000000000118/complete-catch-up",
                "/v1/replay/018f2e3a700070008000000000000118/continue-live",
            ];
            for (index, expected_path) in expected.into_iter().enumerate() {
                let (path, body) = read_request(&mut stream).await;
                assert_eq!(path, expected_path);
                if index == 1 {
                    server_acknowledged_count.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["cursor"],
                        "gocode-replay-cursor-v1.7b7d"
                    );
                }
                if index == 3 {
                    server_acknowledged_count.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["cursor"],
                        "gocode-replay-cursor-v1.7b2261223a317d"
                    );
                }
                let response = match index {
                    0 => serde_json::json!({
                        "sessionId": "018f2e3a700070008000000000000118",
                        "highWaterRef": "aa",
                        "events": [fixture()],
                        "hasMore": true
                    }),
                    1 | 3 => serde_json::json!({"acknowledged": true}),
                    2 => {
                        let mut event = fixture();
                        event["eventId"] =
                            serde_json::json!("018f2e3a-7000-7000-8000-000000000119");
                        event["eventType"] = serde_json::json!("conversation.closed");
                        event["payload"] = serde_json::json!({"type": "conversation.closed"});
                        event["sequence"] = serde_json::json!(3);
                        event["cursor"] =
                            serde_json::json!("gocode-replay-cursor-v1.7b2261223a317d");
                        serde_json::json!({"events": [event], "hasMore": false})
                    }
                    4 => serde_json::json!({
                        "catchUpProof": "aa",
                        "sessionState": "catch_up_complete"
                    }),
                    5 => serde_json::json!({
                        "liveDeliveryId": "018f2e3a-7000-7000-8000-000000000117",
                        "sessionState": "live"
                    }),
                    _ => unreachable!(),
                };
                write_json(&mut stream, &response).await;
            }
        });

        let client = test_client(address);
        let scope = ReplayScope::new(
            ReplayAggregateKind::Conversation,
            CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
        );
        let mut applied = Vec::new();
        let mut emitted = Vec::new();
        let live = client
            .catch_up_from_persisted_cursor(
                scope,
                None,
                ReplayIdentityTracker::new(),
                |delivery| {
                    applied.push(delivery.event_id());
                    Ok::<_, ()>(delivery.event_id())
                },
                |event_id| {
                    assert!(
                        acknowledged_count.load(Ordering::SeqCst) > emitted.len(),
                        "renderer update must follow the corresponding server ack"
                    );
                    emitted.push(event_id);
                },
            )
            .await
            .unwrap();

        assert_eq!(applied.len(), 2);
        assert_eq!(emitted, applied);
        assert_eq!(live.scope(), scope);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn persisted_cursor_is_validated_before_open_session() {
        let client = test_client("127.0.0.1:9".parse().unwrap());
        let scope = ReplayScope::new(
            ReplayAggregateKind::Conversation,
            CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
        );
        let result = client
            .catch_up_from_persisted_cursor(
                scope,
                Some("not-a-runtime-cursor"),
                ReplayIdentityTracker::new(),
                |_| Ok::<_, ()>(()),
                |()| {},
            )
            .await;
        let Err(error) = result else {
            panic!("invalid stored cursor accepted");
        };
        assert_eq!(error.kind(), ReplayClientErrorKind::CursorInvalid);
    }

    #[tokio::test]
    async fn http_rejects_unexpected_content_type_and_oversized_body_before_callback() {
        let cases = [
            (
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\n{}"
                    .to_owned(),
                ReplayClientErrorKind::UnexpectedContentType,
            ),
            (
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                    MAXIMUM_REPLAY_RESPONSE_BYTES + 1
                ),
                ReplayClientErrorKind::ResponseTooLarge,
            ),
        ];

        for (response, expected) in cases {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (path, _) = read_request(&mut stream).await;
                assert_eq!(path, "/v1/replay/open-session");
                stream.write_all(response.as_bytes()).await.unwrap();
            });
            let client = test_client(address);
            let scope = ReplayScope::new(
                ReplayAggregateKind::Conversation,
                CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
            );
            let mut callbacks = 0;
            let result = client
                .catch_up(scope, None, |_| {
                    callbacks += 1;
                    Ok::<_, ()>(())
                })
                .await;
            let Err(error) = result else {
                panic!("invalid response must fail before callback");
            };
            assert_eq!(error.kind(), expected);
            assert_eq!(callbacks, 0);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn live_delivery_requires_local_ack_before_reading_another_frame() {
        let mut live = test_live_session();
        let event = live_delivery_fixture(1);
        let decoded = live
            .decode_stream_frame(RawSseFrame::Delivery(serde_json::to_vec(&event).unwrap()))
            .unwrap();
        assert!(matches!(decoded, ReplayStreamEvent::Delivery(_)));

        assert_eq!(
            live.next_event().await.unwrap_err().kind(),
            ReplayClientErrorKind::LocalCallback
        );
    }

    #[tokio::test]
    async fn live_session_returns_eof_to_the_outer_reconnect_owner() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (path, _) = read_request(&mut stream).await;
            assert_eq!(path, "/v1/replay/018f2e3a700070008000000000000118/events");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let mut live = test_live_session_with_client(test_client(address));

        assert_eq!(
            live.next_event().await.unwrap_err().kind(),
            ReplayClientErrorKind::Transport
        );
        server.await.unwrap();
    }

    #[test]
    fn live_delivery_sequence_must_start_at_one_and_remain_contiguous() {
        let mut live = test_live_session();
        assert_eq!(
            live.decode_stream_frame(RawSseFrame::Delivery(
                serde_json::to_vec(&live_delivery_fixture(2)).unwrap()
            ))
            .unwrap_err()
            .kind(),
            ReplayClientErrorKind::NonMonotonicSequence
        );
    }
