// NM-06 E2E residual boundary: an ALREADY-STARTED live SSE stream keeps the
// SAME 200 response body. 401 is impossible once headers are sent, so the
// first producer poll after revocation must fail the stream closed IN BAND:
// an `event: terminal` frame with code `replay_authorization_revoked`, then a
// clean end of the stream — and the post-revocation event must never be
// serialized into any frame.

#[cfg(feature = "test-support")]
async fn nm07_next_sse_frame(
    stream: &mut (impl futures::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin),
) -> Option<Vec<u8>> {
    use futures::StreamExt as _;
    tokio::time::timeout(Duration::from_secs(10), stream.next())
        .await
        .unwrap()
        .map(|frame| frame.unwrap().to_vec())
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn nm06_open_sse_stream_terminates_in_band_after_revocation_and_new_event() {
    let representations = representations();
    let directory = tempfile::tempdir().unwrap();
    let runtime_root = directory.path().join("runtime");
    let daemon_dir = runtime_root.join("runne-daemon");
    std::fs::create_dir_all(&daemon_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for dir in [&runtime_root, &daemon_dir] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let db_path = daemon_dir.join("nm07-live-sse.sqlite");
    let setup_connection = open_managed_connection(&db_path, ConnectionMode::Writer).unwrap();
    apply_migrations(&setup_connection).unwrap();
    ensure_authority_id(&setup_connection, &AUTHORITY).unwrap();
    let lineage = ensure_event_log_lineage_id(&setup_connection).unwrap();
    readiness_from_managed(&setup_connection).unwrap();
    publication_from_managed(&setup_connection).unwrap();
    drop(setup_connection);
    let authority = RuntimeAuthorityId("nm07-live-sse-e2e".into());
    let guard: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let store = StoreTransaction::open(
        db_path.to_str().unwrap(),
        authority.clone(),
        Arc::clone(&guard),
    )
    .unwrap();
    seed_canonical_workspace(&store);
    set_project_trust(&db_path, ProjectTrustStatus::Trusted);
    let trust_store = runne_store::ProjectTrustStore::open(&db_path, TRUST_AUTHORITY).unwrap();
    let trust_authority: Arc<ProjectTrustPolicyAuthority> = Arc::new(
        runne_security::project_trust_policy::ProjectTrustPolicyAuthority::new(Arc::new(
            trust_store,
        ))
        .with_byte_inspection(Arc::clone(&guard)),
    );
    let taskrun_service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(), store.clone(), store.clone(), authority.clone(),
    ));
    let text_service: Arc<dyn ConversationTextCommandService> = Arc::new(
        ConversationTextService::new(store.clone(), store.clone(), authority.clone(), Arc::clone(&guard)),
    );
    let (handle, mut controller) = Runtime::start_borrowed_with_conversations(
        runne_runtime::TokioRuntimeContext::new_for_test(),
        taskrun_service, text_service, RuntimeConfig::default(),
    )
    .unwrap();
    let host = RuntimeCanonicalConversationHost::new(
        handle,
        Arc::new(ConversationService::new(store.clone(), store.clone(), authority)),
        store.clone(),
        CleanProvider { calls: Arc::new(AtomicUsize::new(0)) },
        Arc::clone(&guard),
    );
    let conversation_id: ConversationId = CONVERSATION_ID.parse().unwrap();
    host.create_conversation(
        conversation_context(1, "nm07-create"),
        CreateCanonicalConversationCommand {
            conversation_id,
            workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .await
    .unwrap();
    host.generate_text(
        conversation_context(2, "nm07-first"),
        GenerateConversationTextCommand {
            conversation_id,
            expected_version: 1,
            text: CanonicalMessageText::new("first trusted input").unwrap(),
        },
    )
    .await
    .unwrap();
    let new_input = "third live input after revocation";
    let new_reply = "clean reply to: third live input after revocation";

    let binding = authenticated_runtime_session(lineage).binding;
    let mut session_service = LocalSessionService::new(binding.clone(), TOKEN);
    let challenge = session_service
        .issue_challenge([0x61; 32], [0x62; 32], Duration::ZERO)
        .unwrap();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&TOKEN).unwrap();
    mac.update(&bootstrap_proof_transcript(&binding, [0x62; 32], [0x61; 32]));
    session_service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            SESSION_AUTHORITY,
            Duration::ZERO,
        )
        .unwrap();
    let local_session = Arc::new(Mutex::new(session_service));
    let replay = replay_router(
        ReplayHttpState::new(
            ReplayService::new(
                Arc::new(ReplayStore::new(open_admitted_fixture_connection(&db_path, lineage)))
                    as Arc<dyn runne_application::replay_service::ReplayStorePort>,
                [0x77; 32],
                lineage,
                runne_daemon::application::replay_authorization_fixture::with_trust(
                    AUTHORITY,
                    Arc::clone(&local_session),
                    Arc::clone(&trust_authority),
                    &store,
                ),
            ),
            ReplayHttpBinding::new(AUTHORITY, 1, 0).unwrap(),
            LimitsConfig::default(),
            Arc::clone(&guard),
        ),
    )
    .layer(session_layer(lineage))
    .layer(axum::middleware::from_fn(request_id_middleware));

    // Trusted: open (initial delivery) -> acknowledge -> complete catch-up
    // -> live epoch.
    let response = replay
        .clone()
        .oneshot(open_session_request(&conversation_id))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let opened: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    let session_hex = opened["sessionId"].as_str().unwrap().to_owned();
    let cursor = opened["events"].as_array().unwrap().last().unwrap()["cursor"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = replay
        .clone()
        .oneshot(nm06_acknowledge_request(&session_hex, &cursor))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "acknowledged delivery");
    let response = replay
        .clone()
        .oneshot(nm06_complete_catch_up_request(&session_hex))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "catch-up completion");
    let response = replay
        .clone()
        .oneshot(continue_live_request(&session_hex))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "live epoch while trusted");
    // Trusted append in the live epoch, BEFORE the SSE GET: the initial poll
    // inside GET /events must deliver it on the already-open body.
    host.generate_text(
        conversation_context(3, "nm07-second-trusted"),
        GenerateConversationTextCommand {
            conversation_id,
            expected_version: 3,
            text: CanonicalMessageText::new("second trusted input").unwrap(),
        },
    )
    .await
    .unwrap();

    // Open the live stream while trusted: 200 and SSE headers are committed
    // BEFORE the body is consumed — a 401 is impossible on this body.
    let response = replay
        .oneshot(nm06_events_request(&session_hex))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "live stream must start while trusted",
    );
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream",
        "in-flight SSE body",
    );
    let mut stream = response.into_body().into_data_stream();
    let initial = nm07_next_sse_frame(&mut stream).await.unwrap();
    assert!(
        String::from_utf8_lossy(&initial).contains("event: delivery"),
        "initial live delivery must arrive on the open body",
    );
    assert_absent("nm07 initial live delivery", &initial, &representations);

    // Revoke, then append a NEW event; the write path is not trust-gated.
    set_project_trust(&db_path, ProjectTrustStatus::Untrusted);
    host.generate_text(
        conversation_context(4, "nm07-third-revoked"),
        GenerateConversationTextCommand {
            conversation_id,
            expected_version: 5,
            text: CanonicalMessageText::new(new_input).unwrap(),
        },
    )
    .await
    .unwrap();

    // Keep reading the SAME body: the next producer poll re-checks trust and
    // must end the stream with the in-band terminal frame.
    let mut after_revoke = Vec::new();
    loop {
        let frame = nm07_next_sse_frame(&mut stream).await
            .expect("live stream must end with an in-band terminal frame, not EOF");
        let terminal = String::from_utf8_lossy(&frame).contains("event: terminal");
        after_revoke.extend_from_slice(&frame);
        if terminal {
            break;
        }
    }
    let tail = String::from_utf8(after_revoke.clone()).unwrap();
    assert!(
        tail.contains("replay_authorization_revoked"),
        "terminal frame must name the revocation: {tail}"
    );
    assert_absent("nm07 live frames after revocation", &after_revoke, &representations);
    assert!(!tail.contains(new_input) && !tail.contains(new_reply));
    assert!(
        nm07_next_sse_frame(&mut stream).await.is_none(),
        "terminal frame must be the last frame of the body"
    );

    let outcome = controller
        .shutdown(ShutdownMode::Graceful {
            timeout: std::time::Duration::from_secs(5),
        })
        .await;
    assert!(!matches!(outcome, ShutdownOutcome::Incomplete { .. }));
}
