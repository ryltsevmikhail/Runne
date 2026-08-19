#[tokio::test]
async fn empty_catch_up_has_server_issued_proof() {
    let store = store();
    let (session, events) = store
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
        .await
        .unwrap()
        .into_opened()
        .unwrap();
    assert!(events.is_empty());
    let (completed, last_ack_event) = store
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
    assert_eq!(completed.state, ReplayState::CatchUpComplete);
    assert!(last_ack_event.is_none());
    assert_eq!(
        completed.catch_up_completion.as_ref().map(Vec::len),
        Some(32)
    );
}

#[tokio::test]
async fn nonempty_catch_up_requires_acknowledgement() {
    let store = store();
    let (session, _) = store
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
        .await
        .unwrap()
        .into_opened()
        .unwrap();
    let error = store
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
        .unwrap_err();
    assert!(matches!(error, ReplayError::NotAcknowledged));
}

#[tokio::test]
async fn test_open_session_returns_empty_for_empty_db() {
    let store = store();

    let (_, events) = open(&store, None).await;

    assert!(events.is_empty());
}

#[tokio::test]
async fn test_open_session_with_events_returns_all_events() {
    let store = store_with_events(3);

    let (_, events) = open(&store, None).await;

    assert_eq!(
        events
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
}

#[tokio::test]
async fn test_from_cursor_inclusive() {
    let store = store_with_events(3);

    let (_, events) = open(&store, Some(&cursor(2))).await;

    assert_eq!(
        events
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>(),
        [2, 3]
    );
}

#[tokio::test]
async fn open_session_rejects_cursor_for_unknown_event_position() {
    let store = store_with_events(1);

    let error = store
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            0,
            1,
            &AGGREGATE,
            Some(&cursor(2)),
            &EventLogLineageId::from_bytes(LINEAGE),
            &SECRET,
            delivery_guard(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::CursorInvalid { reason: _ }));
}

#[tokio::test]
async fn test_read_page_pagination() {
    let store = store_with_events(102);
    let (session, initial_events) = open(&store, None).await;
    assert_eq!(initial_events.len(), 100);

    let first_page = store
        .read_page(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            1,
            delivery_guard(),
        )
        .await
        .unwrap();
    let second_page = store
        .read_page(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            1,
            delivery_guard(),
        )
        .await
        .unwrap();

    assert_eq!(first_page.1[0].global_position, 101);
    assert_eq!(second_page.1[0].global_position, 102);
    assert!(first_page.0.next_page_position.is_some());
    assert!(second_page.0.next_page_position.is_none());
}

#[tokio::test]
async fn exact_full_initial_page_can_complete_after_acknowledgement() {
    let store = store_with_events(100);
    let (session, initial_events) = open(&store, None).await;
    assert_eq!(initial_events.len(), 100);

    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(100),
            delivery_guard(),
        )
        .await
        .unwrap();

    let (completed, last_ack_event) = store
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

    assert_eq!(completed.state, ReplayState::CatchUpComplete);
    assert_eq!(last_ack_event.unwrap().global_position, 100);
}

#[tokio::test]
async fn catch_up_completion_uses_last_event_in_scope() {
    let store = store_with_scoped_and_unrelated_event();
    let (session, initial_events) = open(&store, None).await;
    assert_eq!(
        initial_events
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>(),
        [1]
    );

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

    let (completed, last_ack_event) = store
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

    assert_eq!(completed.state, ReplayState::CatchUpComplete);
    assert_eq!(last_ack_event.unwrap().global_position, 1);
}
