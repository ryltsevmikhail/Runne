#[tokio::test(flavor = "current_thread")]
async fn prohibited_material_is_absent_from_current_durable_and_outbound_boundaries() {
    let tracing_bytes = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&tracing_bytes);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || CaptureWriter(Arc::clone(&capture)))
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);

    let representations = representations();
    let directory = tempfile::tempdir().unwrap();
    let db_path = directory.path().join("prohibited-content.sqlite");
    let authority = RuntimeAuthorityId("task-seven-e2e".into());
    let mut broker = SecretBroker::new();
    broker
        .register("task-seven-inert", MARKER.as_bytes().to_vec())
        .unwrap();
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(broker.prohibited_content_guard());
    let store = StoreTransaction::open(
        db_path.to_str().unwrap(),
        authority.clone(),
        Arc::clone(&guard),
    )
    .unwrap();
    let taskrun_service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority.clone(),
    ));
    let text_service: Arc<dyn ConversationTextCommandService> =
        Arc::new(ConversationTextService::new(
            store.clone(),
            store.clone(),
            authority.clone(),
            Arc::clone(&guard),
        ));
    let (handle, mut controller) = Runtime::start_borrowed_with_conversations(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
        taskrun_service,
        text_service,
        RuntimeConfig::default(),
    )
    .unwrap();
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let host = RuntimeCanonicalConversationHost::new(
        handle,
        Arc::new(ConversationService::new(
            store.clone(),
            store.clone(),
            authority,
        )),
        store.clone(),
        MarkerProvider {
            calls: Arc::clone(&provider_calls),
        },
        Arc::clone(&guard),
    );
    let conversation_id: ConversationId = CONVERSATION_ID.parse().unwrap();
    host.create_conversation(
        conversation_context(1, "create-e2e"),
        CreateCanonicalConversationCommand {
            conversation_id,
            workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        },
    )
    .await
    .unwrap();

    let prohibited_user = host
        .generate_text(
            conversation_context(2, "prohibited-user"),
            GenerateConversationTextCommand {
                conversation_id,
                expected_version: 1,
                text: CanonicalMessageText::new(MARKER).unwrap(),
            },
        )
        .await;
    assert_eq!(
        prohibited_user,
        Err(ConversationHostError::ProhibitedSecretMaterial)
    );

    let prohibited_assistant = host
        .generate_text(
            conversation_context(3, "prohibited-assistant"),
            GenerateConversationTextCommand {
                conversation_id,
                expected_version: 1,
                text: CanonicalMessageText::new("ordinary user input").unwrap(),
            },
        )
        .await;
    assert_eq!(
        prohibited_assistant,
        Err(ConversationHostError::ProviderOutputRejected)
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);

    let connection = open_with_pragmas(db_path.to_str().unwrap()).unwrap();
    let mut statement = connection
        .prepare(
            "SELECT idempotency_key, command_outcome
             FROM command_receipts ORDER BY command_id",
        )
        .unwrap();
    let mut receipt_bytes = Vec::new();
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .unwrap();
    for row in rows {
        let (key, outcome) = row.unwrap();
        receipt_bytes.extend_from_slice(&key);
        receipt_bytes.extend_from_slice(&outcome);
    }
    assert_absent("receipt query", &receipt_bytes, &representations);
    drop(statement);

    let lineage = ensure_event_log_lineage_id(&connection).unwrap();
    let authenticated = authenticated_runtime_session(lineage);
    drop(connection);
    let replay_connection = open_with_pragmas(db_path.to_str().unwrap()).unwrap();
    let replay_service = ReplayService::new(
        Arc::new(ReplayStore::new(replay_connection)),
        [0x77; 32],
        lineage,
        Arc::new(AvailableReplayAuthorization),
    );
    let replay_state = ReplayHttpState::new(
        replay_service,
        ReplayHttpBinding::new(AUTHORITY, 1, 0).unwrap(),
        LimitsConfig::default(),
        Arc::clone(&guard),
    );
    let replay = replay_router(replay_state)
        .layer(axum::Extension(authenticated))
        .layer(AuthLayer::new(TOKEN))
        .layer(axum::middleware::from_fn(request_id_middleware));
    let response = replay
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/replay/open-session")
                .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "aggregateType": "conversation",
                        "aggregateId": hex::encode(conversation_id.as_bytes()),
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let replay_status = response.status();
    let replay_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "unexpected replay response: {}",
        String::from_utf8_lossy(&replay_bytes)
    );
    assert_absent("replay response", &replay_bytes, &representations);

    let exporter = VerificationExporter::new(Arc::clone(&guard));
    let export_bytes = exporter
        .export_run_json(
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            "completed",
            Some("passed"),
            0,
        )
        .unwrap();
    assert_absent("synthetic export", &export_bytes, &representations);
    assert!(
        exporter
            .export_run_json(uuid::Uuid::now_v7(), uuid::Uuid::now_v7(), MARKER, None, 0,)
            .is_err()
    );

    let backup = InMemoryBackupStore::new(Arc::clone(&guard));
    let manifest = backup
        .create_backup(
            vec![StreamInventory {
                stream_name: "verification_run".into(),
                event_count: 1,
                first_sequence: 1,
                last_sequence: 1,
            }],
            VerificationDigest::from_bytes([1; 32]),
        )
        .unwrap();
    let backup_bytes = backup.archive_bytes(&manifest.backup_id).unwrap();
    assert_absent("synthetic backup", &backup_bytes, &representations);
    assert!(
        backup
            .create_backup(
                vec![StreamInventory {
                    stream_name: MARKER.into(),
                    event_count: 1,
                    first_sequence: 1,
                    last_sequence: 1,
                }],
                VerificationDigest::from_bytes([1; 32]),
            )
            .is_err()
    );

    let recording_provider = RecordingProvider::default();
    let repository = UnreachableRepository;
    let admission = UnreachableAdmission;
    let coordinator = ProviderDispatchCoordinator::new(
        &repository,
        &admission,
        &recording_provider,
        guard.as_ref(),
    );
    assert_eq!(
        coordinator.dispatch(provider_request()).await,
        Err(ProviderAdmissionError::PolicyDenied)
    );
    assert_absent(
        "recording provider input",
        &recording_provider.prepared_bytes.lock().unwrap(),
        &representations,
    );

    let canonical_error = canonical_error_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        "prohibited_secret_material",
        &RequestId::generate(),
    );
    let canonical_error_bytes = to_bytes(canonical_error.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_absent("canonical error", &canonical_error_bytes, &representations);

    assert_eq!(
        controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await,
        ShutdownOutcome::Quiesced
    );
    drop(host);
    drop(store);

    for (kind, path) in [
        ("database", db_path.clone()),
        ("wal", db_path.with_extension("sqlite-wal")),
        ("shm", db_path.with_extension("sqlite-shm")),
    ] {
        let bytes = std::fs::read(path).unwrap_or_default();
        assert_absent(kind, &bytes, &representations);
    }
    assert_absent(
        "tracing buffer",
        &tracing_bytes.lock().unwrap(),
        &representations,
    );
}
