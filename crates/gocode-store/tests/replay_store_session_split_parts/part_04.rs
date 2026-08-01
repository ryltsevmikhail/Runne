#[tokio::test]
async fn failed_live_activation_never_persists_an_intermediate_state() {
    let (store, observer, _directory) = file_store_with_events(0);
    let (session, _) = open(&store, None).await;
    store
        .complete_catch_up(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &SECRET,
            delivery_guard(),
        )
        .await
        .unwrap();
    observer
        .execute_batch(
            "
            CREATE TRIGGER fail_live_activation
            BEFORE UPDATE OF state ON _replay_subscriptions
            WHEN NEW.state = 'live'
            BEGIN
                SELECT RAISE(ABORT, 'injected live activation failure');
            END;
            ",
        )
        .unwrap();

    let error = store
        .continue_live(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            delivery_guard(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::Storage(_)));
    let state: String = observer
        .query_row(
            "SELECT state FROM _replay_subscriptions WHERE session_id = ?1",
            [session.session_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "catch_up_complete");
}

#[tokio::test]
async fn poll_live_advances_past_delivered_events() {
    let (store, writer, _directory) = file_store_with_events(1);
    let (session, _) = open(&store, None).await;
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
            delivery_guard(),
        )
        .await
        .unwrap();
    store
        .complete_catch_up(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &SECRET,
            delivery_guard(),
        )
        .await
        .unwrap();
    store
        .continue_live(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            delivery_guard(),
        )
        .await
        .unwrap();

    let row = taskrun_row(AGGREGATE, 2, 2);
    writer
        .execute(
            "INSERT INTO events \
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
             VALUES (?1, 1, ?2, 2, 2, 0, 0, 1, NULL, ?1, ?3, ?4, ?5, ?6, ?2, 1, 1)",
            rusqlite::params![
                row.event_id.as_slice(),
                AGGREGATE.as_slice(),
                row.idempotency_key,
                row.actor,
                row.payload,
                row.integrity_digest.as_slice(),
            ],
        )
        .unwrap();
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = 2, last_event_id = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            rusqlite::params![row.event_id.as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();

    let first = store
        .poll_live(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            delivery_guard(),
        )
        .await
        .unwrap();
    let second = store
        .poll_live(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            delivery_guard(),
        )
        .await
        .unwrap();

    assert_eq!(
        first
            .1
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>(),
        [2]
    );
    assert!(second.1.is_empty());
}

#[tokio::test]
async fn replay_rejects_interior_sequence_gap() {
    let (store, writer, _directory) = file_store_with_events(3);
    writer
        .execute("DELETE FROM events WHERE global_position = 2", [])
        .unwrap();

    let result = store
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            0,
            1,
            &AGGREGATE,
            None,
            &EventLogLineageId::from_bytes(LINEAGE),
            &SECRET,
            delivery_guard(),
        )
        .await;

    assert!(matches!(
        result,
        Ok(gocode_application::ports::ReplayOpenResult::RetentionGap { .. })
    ));
}

#[tokio::test]
async fn poll_live_rejects_sequence_jump() {
    let (store, writer, _directory) = file_store_with_events(1);
    let (session, _) = open(&store, None).await;
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(1),
            delivery_guard(),
        )
        .await
        .unwrap();
    store
        .complete_catch_up(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &SECRET,
            delivery_guard(),
        )
        .await
        .unwrap();
    store
        .continue_live(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            delivery_guard(),
        )
        .await
        .unwrap();

    let row = taskrun_row(AGGREGATE, 3, 2);
    writer
        .execute(
            "INSERT INTO events \
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
             VALUES (?1, 1, ?2, 3, 2, 0, 0, 1, NULL, ?1, ?3, ?4, ?5, ?6, ?2, 1, 1)",
            rusqlite::params![
                row.event_id.as_slice(),
                AGGREGATE.as_slice(),
                row.idempotency_key,
                row.actor,
                row.payload,
                row.integrity_digest.as_slice(),
            ],
        )
        .unwrap();
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = 3, last_event_id = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            rusqlite::params![row.event_id.as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();

    let result = store
        .poll_live(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            delivery_guard(),
        )
        .await;

    assert!(matches!(result, Err(ReplayError::Integrity(_))));
}
