#[tokio::test]
async fn test_acknowledge_monotonic() {
    let store = store_with_events(2);
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
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(2),
            delivery_guard(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_acknowledge_duplicate_idempotent() {
    let store = store_with_events(1);
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
}

#[tokio::test]
async fn acknowledge_rejects_cursor_not_delivered_by_session() {
    let store = store_with_events(1);
    let (session, _) = open(&store, None).await;
    let mut forged_cursor = cursor(1);
    forged_cursor.event_id = EventId::from_bytes([0xEE; 16]);

    let error = store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &forged_cursor,
            delivery_guard(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::CursorInvalid { reason: _ }));
}

#[tokio::test]
async fn test_complete_catch_up_requires_ack() {
    let store = store_with_events(1);
    let (session, _) = open(&store, None).await;

    let error = store
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
        .unwrap_err();

    assert!(matches!(error, ReplayError::NotAcknowledged));
}

#[tokio::test]
async fn test_complete_catch_up_success() {
    let store = store_with_events(2);
    let (session, _) = open(&store, None).await;
    store
        .acknowledge(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            &cursor(2),
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
    assert_eq!(last_ack_event.unwrap().global_position, 2);
}

#[tokio::test]
async fn duplicate_complete_catch_up_returns_same_server_proof() {
    let store = store_with_events(1);
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

    let first = store
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
    let second = store
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

    assert_eq!(first.0.catch_up_completion, second.0.catch_up_completion);
    assert_eq!(first.1.unwrap().global_position, 1);
    assert_eq!(second.1.unwrap().global_position, 1);
    assert_eq!(second.0.state, ReplayState::CatchUpComplete);
}

#[tokio::test]
async fn test_continue_live_cas() {
    let store = store_with_events(1);
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

    let first = store
        .continue_live(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            delivery_guard(),
        )
        .await;
    let second = store
        .continue_live(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            0,
            delivery_guard(),
        )
        .await;

    assert!(matches!(
        first,
        Ok(ReplaySession {
            state: ReplayState::Live,
            ..
        })
    ));
    assert!(matches!(second, Err(ReplayError::InvalidState(_))));
}
