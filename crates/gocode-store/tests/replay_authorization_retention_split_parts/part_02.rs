fn store_with_events(count: i64) -> ReplayStore {
    let connection = managed_memory();
    connection
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (1, ?1, ?2, ?3, 0, 0)",
            rusqlite::params![AGGREGATE.as_slice(), count, event_id(count).as_slice()],
        )
        .unwrap();
    for position in 1..=count {
        insert_taskrun_event(&connection, position, position);
    }
    ReplayStore::new(connection)
}

fn file_store_with_events(count: i64) -> (ReplayStore, Connection, TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replay.sqlite");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (1, ?1, ?2, ?3, 0, 0)",
            rusqlite::params![AGGREGATE.as_slice(), count, event_id(count).as_slice()],
        )
        .unwrap();
    for position in 1..=count {
        insert_taskrun_event(&connection, position, position);
    }
    let observer = Connection::open(&path).unwrap();
    (ReplayStore::new(connection), observer, directory)
}

fn service(store: ReplayStore, authorization: MutableAuthorization) -> ReplayService {
    ReplayService::new(
        Arc::new(store),
        SECRET,
        EventLogLineageId::from_bytes(LINEAGE),
        Arc::new(authorization),
    )
}

fn scope() -> ReplayScope {
    ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: AGGREGATE,
    }
}

#[tokio::test]
async fn revocation_after_page_selection_returns_no_page_and_preserves_progress() {
    let (store, observer, _directory) = file_store_with_events(101);
    let authorization = MutableAuthorization::new(7, Sensitivity::Sensitive);
    let service = service(store.clone(), authorization.clone());
    let (session, _) = service
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
    let before = session.last_delivered_position;

    let error = service
        .read_page(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            7,
            1,
            Arc::new(RevokingDeliveryGuard(authorization)),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
    let persisted: Option<i64> = observer
        .query_row(
            "SELECT last_delivered_position
             FROM _replay_subscriptions
             WHERE session_id = ?1",
            [session.session_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(persisted, before);
}

#[tokio::test]
async fn revocation_after_ack_validation_preserves_acknowledged_cursor() {
    let (store, observer, _directory) = file_store_with_events(1);
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
    authorization.revoke_after_next_lease();

    let error = service
        .acknowledge(&session.session_id, "principal", 1, &AUTHORITY, 7, &cursor)
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
    let last_acked: Option<i64> = observer
        .query_row(
            "SELECT last_acked_position FROM _replay_subscriptions WHERE session_id = ?1",
            [session.session_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_acked, None);
}

#[tokio::test]
async fn revocation_immediately_before_catch_up_completion_preserves_session_state() {
    let (store, observer, _directory) = file_store_with_events(1);
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
    authorization.revoke_after_next_lease();

    let error = service
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 7)
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
    let (state, proof): (String, Option<Vec<u8>>) = observer
        .query_row(
            "SELECT state, catch_up_completion
             FROM _replay_subscriptions
             WHERE session_id = ?1",
            [session.session_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "catching_up");
    assert_eq!(proof, None);
}

#[tokio::test]
async fn revocation_immediately_before_live_activation_preserves_completed_state() {
    let (store, observer, _directory) = file_store_with_events(1);
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
    authorization.revoke_after_next_lease();

    let error = service
        .continue_live(&session.session_id, "principal", 1, &AUTHORITY, 7)
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
    let (state, live_delivery_id): (String, Option<Vec<u8>>) = observer
        .query_row(
            "SELECT state, live_delivery_id
             FROM _replay_subscriptions
             WHERE session_id = ?1",
            [session.session_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "catch_up_complete");
    assert_eq!(live_delivery_id, None);
}
