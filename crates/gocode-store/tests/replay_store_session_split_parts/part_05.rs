#[tokio::test]
async fn replay_rejects_payload_changed_without_integrity_digest_update() {
    let (store, writer, _directory) = file_store_with_events(1);
    writer
        .execute(
            "UPDATE events SET payload = x'000102' WHERE global_position = 1",
            [],
        )
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

    assert!(matches!(result, Err(ReplayError::Integrity(_))));
}

#[tokio::test]
async fn test_close_session() {
    let store = store();
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

    store
        .close_session(&session.session_id, "principal", 1, &AUTHORITY, 0)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_reconnect_from_ack() {
    let store = store_with_events(3);
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

    let (_, events) = open(&store, Some(&cursor(2))).await;

    assert_eq!(
        events
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>(),
        [2, 3]
    );
}
