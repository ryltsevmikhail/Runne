fn setup_with_events(
    idempotency_keys: Vec<String>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
) -> (axum::Router, ReplayTestDatabase) {
    assert!(!idempotency_keys.is_empty());
    let directory = tempfile::tempdir().unwrap();
    let daemon_dir = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database_path = daemon_dir.join("replay.sqlite");
    let connection = open_managed_connection(&database_path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    ensure_authority_id(&connection, &AUTHORITY).unwrap();
    ensure_exact_event_log_lineage_id(&connection, EventLogLineageId::from_bytes(LINEAGE)).unwrap();
    let event_count = i64::try_from(idempotency_keys.len()).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams \
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) \
             VALUES (1, ?1, ?2, ?3, 0, 0)",
            rusqlite::params![
                AGGREGATE.as_slice(),
                event_count,
                event_id(event_count).as_slice()
            ],
        )
        .unwrap();
    for (index, idempotency_key) in idempotency_keys.into_iter().enumerate() {
        let position = i64::try_from(index + 1).unwrap();
        let row = taskrun_row(position, position, idempotency_key);
        connection
            .execute(
                "INSERT INTO events \
                 (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
                  sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
                  payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
                 VALUES (?1, 1, ?2, ?3, ?3, 0, 0, 1, NULL, ?1, ?4, ?5, ?6, ?7, ?2, 1, 1)",
                rusqlite::params![
                    row.event_id.as_slice(),
                    AGGREGATE.as_slice(),
                    position,
                    row.idempotency_key,
                    b"test-actor".as_slice(),
                    row.payload,
                    row.integrity_digest.as_slice(),
                ],
            )
            .unwrap();
    }

    let database = ReplayTestDatabase::capture(directory, database_path, &connection);
    let service = ReplayService::new(
        Arc::new(ReplayTestDatabase::replay_store(connection)),
        [0xDD; 32],
        EventLogLineageId::from_bytes(LINEAGE),
        Arc::new(AvailableReplayAuthorization),
    );
    let state = ReplayHttpState::new(
        service,
        ReplayHttpBinding::new(AUTHORITY, GENERATION, 0).unwrap(),
        LimitsConfig::default(),
        prohibited_content,
    );
    let router = replay_router(state)
        .layer(session_auth_layer())
        .layer(axum::middleware::from_fn(request_id_middleware));
    (router, database)
}

fn subscription_count(database: &ReplayTestDatabase) -> i64 {
    database
        .open_reader()
        .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn replay_progress(
    database: &ReplayTestDatabase,
    session_id: &str,
) -> (String, Option<i64>, Option<i64>, Option<i64>) {
    database
        .open_reader()
        .query_row(
            "SELECT state, next_page_position, last_delivered_position, last_acked_position
             FROM _replay_subscriptions
             WHERE session_id = ?1",
            [hex::decode(session_id).unwrap()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

#[tokio::test]
async fn open_session_classification_denial_leaves_no_durable_session() {
    for guard in [
        Arc::new(DenyGuard(DenyMode::Marker)) as Arc<dyn ProhibitedContentPort>,
        Arc::new(DenyGuard(DenyMode::Unavailable)) as Arc<dyn ProhibitedContentPort>,
    ] {
        let (app, directory) = setup_with(PROHIBITED_MARKER, guard);
        let response = app
            .oneshot(post(
                "/v1/replay/open-session",
                json!({
                    "aggregateType": "taskRun",
                    "aggregateId": aggregate_id_wire(),
                    "fromCursor": null,
                }),
            ))
            .await
            .unwrap();
        assert!(!response.status().is_success());
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(
            !bytes
                .windows(PROHIBITED_MARKER.len())
                .any(|window| window == PROHIBITED_MARKER.as_bytes()),
            "canonical error contained prohibited replay representation"
        );
        assert_eq!(subscription_count(&directory), 0);
    }
}

#[tokio::test]
async fn read_page_classification_denial_preserves_delivery_progress() {
    for denied_mode in [SwitchMode::Marker, SwitchMode::Unavailable] {
        let guard = Arc::new(SwitchableGuard::new(SwitchMode::Available));
        let mut keys = (1..=100)
            .map(|position| format!("replay-page-{position}"))
            .collect::<Vec<_>>();
        keys.push(PROHIBITED_MARKER.to_owned());
        let (app, directory) =
            setup_with_events(keys, Arc::clone(&guard) as Arc<dyn ProhibitedContentPort>);
        let opened = app
            .clone()
            .oneshot(post(
                "/v1/replay/open-session",
                json!({
                    "aggregateType": "taskRun",
                    "aggregateId": aggregate_id_wire(),
                    "fromCursor": null,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(opened.status(), StatusCode::OK);
        let opened = json_body(opened).await;
        let session_id = opened["sessionId"].as_str().unwrap();
        let before = replay_progress(&directory, session_id);
        guard.set(denied_mode);

        let response = app
            .oneshot(post(
                &format!("/v1/replay/{session_id}/read-page"),
                json!({"limit": 1}),
            ))
            .await
            .unwrap();

        assert!(!response.status().is_success());
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(
            !bytes
                .windows(PROHIBITED_MARKER.len())
                .any(|window| window == PROHIBITED_MARKER.as_bytes()),
            "canonical error contained prohibited replay representation"
        );
        assert_eq!(replay_progress(&directory, session_id), before);
    }
}

async fn open_and_continue_live(app: &axum::Router) -> String {
    let opened = app
        .clone()
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": "taskRun",
                "aggregateId": aggregate_id_wire(),
                "fromCursor": null,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::OK);
    let opened = json_body(opened).await;
    let session_id = opened["sessionId"].as_str().unwrap().to_owned();
    let cursor = opened["events"][0]["cursor"].as_str().unwrap();
    let acknowledged = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": cursor}),
        ))
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);
    let completed = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/complete-catch-up"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let continued = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/continue-live"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(continued.status(), StatusCode::OK);
    session_id
}

fn append_taskrun_event(database: &ReplayTestDatabase, position: i64, idempotency_key: &str) {
    let writer = database.open_writer();
    let row = taskrun_row(position, position, idempotency_key.to_owned());
    writer
        .execute(
            "INSERT INTO events \
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
             VALUES (?1, 1, ?2, ?3, ?3, 0, 0, 1, NULL, ?1, ?4, ?5, ?6, ?7, ?2, 1, 1)",
            rusqlite::params![
                row.event_id.as_slice(),
                AGGREGATE.as_slice(),
                position,
                row.idempotency_key,
                b"test-actor".as_slice(),
                row.payload,
                row.integrity_digest.as_slice(),
            ],
        )
        .unwrap();
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = ?1, last_event_id = ?2
             WHERE aggregate_type = 1 AND aggregate_id = ?3",
            rusqlite::params![position, row.event_id.as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();
}
