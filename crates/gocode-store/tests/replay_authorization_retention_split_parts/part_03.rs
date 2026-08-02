#[tokio::test]
async fn live_event_revocation_stops_before_event_and_preserves_progress() {
    let (store, writer, _directory) = file_store_with_events(1);
    let authorization = MutableAuthorization::new(7, Sensitivity::Sensitive);
    let service = service(store, authorization.clone());
    let (session, events) = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            7,
            1,
            &AGGREGATE,
            None,
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap();
    let cursor = service
        .build_cursor_from_event(&events[0], &scope())
        .unwrap();
    service
        .acknowledge(&session.session_id, "principal", 1, &AUTHORITY, 7, &cursor)
        .await
        .unwrap();
    service
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 7)
        .await
        .unwrap();
    service
        .continue_live(&session.session_id, "principal", 1, &AUTHORITY, 7)
        .await
        .unwrap();
    insert_taskrun_event(&writer, 2, 2);
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = 2, last_event_id = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            rusqlite::params![event_id(2).as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();

    let error = service
        .poll_live(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            7,
            Arc::new(RevokingDeliveryGuard(authorization)),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
    let last_delivered: Option<i64> = writer
        .query_row(
            "SELECT last_delivered_position FROM _replay_subscriptions WHERE session_id = ?1",
            [session.session_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_delivered, Some(1));
}

#[tokio::test]
async fn sensitivity_denied_stops_before_session_and_denied_cursor() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    insert_sensitive_conversation_event(&connection);
    let store = ReplayStore::new(connection);
    let service = service(store, MutableAuthorization::new(0, Sensitivity::Public));

    let error = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            0,
            2,
            &AGGREGATE,
            None,
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::SensitivityDenied));
}

#[tokio::test]
async fn sensitivity_boundary_delivers_readable_prefix_and_stops_before_denied_event() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (2, ?1, 2, ?2, 0, 0)",
            rusqlite::params![AGGREGATE.as_slice(), event_id(2).as_slice()],
        )
        .unwrap();
    insert_conversation_event(
        &connection,
        1,
        1,
        ConversationEvent::ConversationCreated {
            workspace_id: WorkspaceId::from_bytes([
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0x31,
            ]),
        },
    );
    insert_conversation_event(
        &connection,
        2,
        2,
        ConversationEvent::UserMessageAppended {
            message_id: MessageId::from_bytes([
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0x32,
            ]),
            taskrun_id: TaskRunId::from_bytes([
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0x33,
            ]),
            attempt_id: AttemptId::from_bytes([
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0x34,
            ]),
            text: MessageText::new("classified").unwrap(),
        },
    );
    let service = service(
        ReplayStore::new(connection),
        MutableAuthorization::new(0, Sensitivity::Public),
    );

    let (session, events) = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            0,
            2,
            &AGGREGATE,
            None,
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].global_position, 1);
    assert_eq!(session.last_delivered_position, Some(1));
    assert!(session.next_page_position.is_some());
    assert!(matches!(
        service
            .read_page(
                &session.session_id,
                "principal",
                1,
                &AUTHORITY,
                0,
                100,
                Arc::new(AvailableDeliveryGuard),
            )
            .await,
        Err(ReplayError::SensitivityDenied)
    ));
}

#[tokio::test]
async fn retained_prefix_gap_returns_authorized_floor_without_cursor_jump() {
    let (store, writer, _directory) = file_store_with_events(3);
    let authorization = MutableAuthorization::new(7, Sensitivity::Sensitive);
    let service = service(store, authorization);
    let (_, events) = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            7,
            1,
            &AGGREGATE,
            None,
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap();
    let cursor = service
        .build_cursor_from_event(&events[0], &scope())
        .unwrap();
    let session_count_before: i64 = writer
        .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| {
            row.get(0)
        })
        .unwrap();
    writer
        .execute("DELETE FROM events WHERE global_position = 1", [])
        .unwrap();

    let error = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            7,
            1,
            &AGGREGATE,
            Some(cursor),
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap_err();

    match error {
        ReplayError::ReplayRetentionGap {
            floor_cursor: Some(floor_cursor),
            gap_range_ref,
        } => {
            assert_eq!(floor_cursor.global_position, 2);
            assert_ne!(gap_range_ref.integrity().as_bytes(), &[0; 32]);
        }
        other => panic!("unexpected gap result: {other:?}"),
    }
    let session_count_after: i64 = writer
        .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(session_count_after, session_count_before);
}
