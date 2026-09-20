// NM-06 E2E: replay authorization re-checks current trust revision per delivery.
use runne_application::project_trust::ProjectTrustStatus;
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn nm06_replay_delivery_rechecks_current_trust_revision() {
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
    let db_path = daemon_dir.join("nm06-replay.sqlite");
    let setup_connection = open_managed_connection(&db_path, ConnectionMode::Writer).unwrap();
    apply_migrations(&setup_connection).unwrap();
    ensure_authority_id(&setup_connection, &AUTHORITY).unwrap();
    let lineage = ensure_event_log_lineage_id(&setup_connection).unwrap();
    readiness_from_managed(&setup_connection).unwrap();
    publication_from_managed(&setup_connection).unwrap();
    drop(setup_connection);
    let authority = RuntimeAuthorityId("nm06-replay-e2e".into());
    let mut broker = SecretBroker::new();
    broker.register("task-seven-inert", MARKER.as_bytes().to_vec()).unwrap();
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(broker.prohibited_content_guard());
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
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let host = RuntimeCanonicalConversationHost::new(
        handle,
        Arc::new(ConversationService::new(store.clone(), store.clone(), authority)),
        store.clone(),
        CleanProvider { calls: Arc::clone(&provider_calls) },
        Arc::clone(&guard),
    );
    let conversation_id: ConversationId = CONVERSATION_ID.parse().unwrap();
    host.create_conversation(
        conversation_context(1, "nm06-create"),
        CreateCanonicalConversationCommand {
            conversation_id,
            workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .await
    .unwrap();
    let delivered = host
        .generate_text(
            conversation_context(2, "nm06-generate"),
            GenerateConversationTextCommand {
                conversation_id,
                expected_version: 1,
                text: CanonicalMessageText::new("trusted clean input").unwrap(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        delivered.assistant_message.text.as_str(),
        "clean reply to: trusted clean input"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);

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
    let with_trust = || {
        runne_daemon::application::replay_authorization_fixture::with_trust(
            AUTHORITY,
            Arc::clone(&local_session),
            Arc::clone(&trust_authority),
            &store,
        )
    };
    let build_state = move |authorization: Arc<dyn ReplayAuthorizationPort>,
                            connection: ManagedConnection| {
        let store_port: Arc<dyn runne_application::replay_service::ReplayStorePort> =
            Arc::new(ReplayStore::new(connection));
        let replay_service =
            ReplayService::new(store_port, [0x77; 32], lineage, authorization);
        ReplayHttpState::new(
            replay_service,
            ReplayHttpBinding::new(AUTHORITY, 1, 0).unwrap(),
            LimitsConfig::default(),
            Arc::clone(&guard),
        )
    };
    // Probe: the delivery gate must admit the trusted project before HTTP.
    let replay = replay_router(build_state(
        with_trust(),
        open_admitted_fixture_connection(&db_path, lineage),
    ))
        .layer(session_layer(lineage))
        .layer(axum::middleware::from_fn(request_id_middleware));

    // Trusted delivery: open succeeds and the page carries the conversation.
    let response = replay
        .clone()
        .oneshot(open_session_request(&conversation_id))
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "unexpected open-session response: {}",
        String::from_utf8_lossy(&body)
    );
    let opened: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_hex = opened["sessionId"].as_str().unwrap().to_owned();
    let response = replay
        .clone()
        .oneshot(read_page_request(&session_hex))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert!(page.windows(6).any(|w| w == b"events"), "page shape");
    assert_absent("nm06 trusted page", &page, &representations);

    // Revoke trust: the previously allowed copy must not survive delivery.
    set_project_trust(&db_path, ProjectTrustStatus::Untrusted);
    expect_replay_denied(
        replay.clone(),
        read_page_request(&session_hex),
        &representations,
        "nm06 denied page",
    )
    .await;

    // Live path: continue-live after revocation must be denied, so no
    // further content can be streamed after the trust change.
    let continue_denied = replay
        .clone()
        .oneshot(continue_live_request(&session_hex))
        .await
        .unwrap();
    assert_ne!(
        continue_denied.status(),
        StatusCode::OK,
        "revoked project must not start a live delivery epoch"
    );

    // Restart: same durable state stays denied in a fresh process.
    drop(replay);
    let restarted = replay_router(build_state(
        with_trust(),
        open_admitted_fixture_connection(&db_path, lineage),
    ))
    .layer(session_layer(lineage))
    .layer(axum::middleware::from_fn(request_id_middleware));
    let response = restarted
        .oneshot(open_session_request(&conversation_id))
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_ne!(status, StatusCode::OK);
    assert_absent("nm06 restarted open", &body, &representations);
    let closed = replay_router(build_state(
        runne_daemon::application::replay_authorization_fixture::closed(
            AUTHORITY,
            Arc::clone(&local_session),
        ),
        open_admitted_fixture_connection(&db_path, lineage),
    ))
    .layer(session_layer(lineage))
    .layer(axum::middleware::from_fn(request_id_middleware));
    let response = closed
        .oneshot(open_session_request(&conversation_id))
        .await
        .unwrap();
    assert_ne!(response.status(), StatusCode::OK, "closed gate denies");

    let outcome = controller
        .shutdown(ShutdownMode::Graceful {
            timeout: std::time::Duration::from_secs(5),
        })
        .await;
    assert!(!matches!(outcome, ShutdownOutcome::Incomplete { .. }));
}

