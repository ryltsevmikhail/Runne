// NM-06 E2E: an already-open live replay session re-checks the CURRENT trust
// revision on EVERY delivery attempt. Initial trusted delivery succeeds
// (open -> read-page -> continue-live), then a revocation plus a NEW
// conversation event must make the next poll of the SAME session fail closed:
// 401 `replay_authorization_revoked` before the SSE stream starts, and the
// new event must not be delivered.

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn nm06_open_live_session_poll_denied_after_revocation_and_new_event() {
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
    let db_path = daemon_dir.join("nm06-live.sqlite");
    let setup_connection = open_managed_connection(&db_path, ConnectionMode::Writer).unwrap();
    apply_migrations(&setup_connection).unwrap();
    ensure_authority_id(&setup_connection, &AUTHORITY).unwrap();
    let lineage = ensure_event_log_lineage_id(&setup_connection).unwrap();
    readiness_from_managed(&setup_connection).unwrap();
    publication_from_managed(&setup_connection).unwrap();
    drop(setup_connection);
    let authority = RuntimeAuthorityId("nm06-live-e2e".into());
    let guard: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let store = StoreTransaction::open(db_path.to_str().unwrap(), authority.clone(), Arc::clone(&guard))
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
        conversation_context(1, "nm06-live-create"),
        CreateCanonicalConversationCommand {
            conversation_id,
            workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .await
    .unwrap();
    host.generate_text(
        conversation_context(2, "nm06-live-first"),
        GenerateConversationTextCommand {
            conversation_id,
            expected_version: 1,
            text: CanonicalMessageText::new("first trusted input").unwrap(),
        },
    )
    .await
    .unwrap();
    let new_input = "second live input after revocation";
    let new_reply = "clean reply to: second live input after revocation";

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
    let initial_events = opened["events"].as_array().unwrap().len();
    assert!(initial_events > 0, "initial delivery must carry the stream");
    let cursor = opened["events"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["cursor"]
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

    // Revoke, then append a NEW event to the same conversation. The write
    // path is not trust-gated, so the event commits — but the open session
    // must not deliver it.
    set_project_trust(&db_path, ProjectTrustStatus::Untrusted);
    host.generate_text(
        conversation_context(4, "nm06-live-second"),
        GenerateConversationTextCommand {
            conversation_id,
            expected_version: 3,
            text: CanonicalMessageText::new(new_input).unwrap(),
        },
    )
    .await
    .unwrap();

    // The next delivery attempt on the SAME session polls live: the gate
    // denies the whole call with 401 `replay_authorization_revoked` before
    // any SSE stream starts, and the new event is not delivered.
    let response = replay
        .oneshot(nm06_events_request(&session_hex))
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED, "live poll must be denied");
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        body.contains("replay_authorization_revoked"),
        "denied live poll must name the revocation: {body}"
    );
    assert_absent("nm06 live poll after revocation", body.as_bytes(), &representations);
    assert!(!body.contains(new_input) && !body.contains(new_reply));

    let outcome = controller
        .shutdown(ShutdownMode::Graceful {
            timeout: std::time::Duration::from_secs(5),
        })
        .await;
    assert!(!matches!(outcome, ShutdownOutcome::Incomplete { .. }));
}

#[cfg(feature = "test-support")]
fn nm06_acknowledge_request(session_hex: &str, cursor: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/v1/replay/{session_hex}/acknowledge"))
        .header("authorization", session_header())
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "cursor": cursor })).unwrap(),
        ))
        .unwrap()
}

#[cfg(feature = "test-support")]
fn nm06_complete_catch_up_request(session_hex: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/v1/replay/{session_hex}/complete-catch-up"))
        .header("authorization", session_header())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap()
}

#[cfg(feature = "test-support")]
fn nm06_events_request(session_hex: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/v1/replay/{session_hex}/events"))
        .header("authorization", session_header())
        .header("accept", "text/event-stream")
        .body(Body::empty())
        .unwrap()
}
