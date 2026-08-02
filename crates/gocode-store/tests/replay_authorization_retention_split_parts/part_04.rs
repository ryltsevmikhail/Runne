#[tokio::test]
async fn revocation_during_gap_computation_releases_no_gap_or_floor_cursor() {
    let (store, writer, _directory) = file_store_with_events(3);
    let authorization = MutableAuthorization::new(7, Sensitivity::Sensitive);
    let service = service(store, authorization.clone());
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
    writer
        .execute("DELETE FROM events WHERE global_position = 1", [])
        .unwrap();
    authorization.revoke_after_next_lease();

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

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
}

#[tokio::test]
async fn retention_manifest_proves_one_contiguous_snapshot() {
    let store = store_with_events(3);

    let manifest = store
        .retention_manifest(&EventLogLineageId::from_bytes(LINEAGE), &SECRET)
        .await
        .unwrap();

    assert_eq!(
        manifest.lineage_id(),
        &EventLogLineageId::from_bytes(LINEAGE)
    );
    assert_eq!(manifest.retention_generation(), 0);
    assert_eq!(manifest.retained_floor(), Some(1));
    assert_eq!(manifest.high_water_position(), 3);
    assert!(manifest.maximum_encoded_event_bytes() > 0);
    assert_ne!(manifest.no_gap_evidence().as_bytes(), &[0; 32]);
}

#[tokio::test]
async fn retention_manifest_measures_actual_hex_transport_payload() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (2, ?1, 1, ?2, 0, 0)",
            rusqlite::params![AGGREGATE.as_slice(), event_id(1).as_slice()],
        )
        .unwrap();
    let payload = ConversationEvent::UserMessageAppended {
        message_id: MessageId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0x21,
        ]),
        taskrun_id: TaskRunId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0x22,
        ]),
        attempt_id: AttemptId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0x23,
        ]),
        text: MessageText::new("x".repeat(MAX_MESSAGE_TEXT_BYTES)).unwrap(),
    };
    let durable_payload_bytes = ConversationEventCodec.encode(&payload).unwrap().len();
    insert_conversation_event(&connection, 1, 1, payload);
    let store = ReplayStore::new(connection);

    let manifest = store
        .retention_manifest(&EventLogLineageId::from_bytes(LINEAGE), &SECRET)
        .await
        .unwrap();

    assert_eq!(
        manifest.maximum_encoded_event_bytes(),
        durable_payload_bytes * 2
    );
}

#[tokio::test]
async fn empty_retention_manifest_has_no_floor_and_zero_high_water() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    let store = ReplayStore::new(connection);

    let manifest = store
        .retention_manifest(&EventLogLineageId::from_bytes(LINEAGE), &SECRET)
        .await
        .unwrap();

    assert_eq!(manifest.retained_floor(), None);
    assert_eq!(manifest.high_water_position(), 0);
    assert_eq!(manifest.maximum_encoded_event_bytes(), 0);
}

#[test]
fn gap_reference_is_bound_to_scope_and_authorization_epoch() {
    let lineage = EventLogLineageId::from_bytes(LINEAGE);
    let first = ReplayStore::build_gap_range_ref(&lineage, 0, 3, 4, &scope(), 7, &SECRET);
    let other_scope = ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: [0xDD; 16],
    };
    let second = ReplayStore::build_gap_range_ref(&lineage, 0, 3, 4, &other_scope, 7, &SECRET);
    let third = ReplayStore::build_gap_range_ref(&lineage, 0, 3, 4, &scope(), 8, &SECRET);

    assert_ne!(first, second);
    assert_ne!(first, third);
}

#[allow(dead_code)]
fn opened(result: ReplayOpenResult) -> (ReplaySession, Vec<ReplayEvent>) {
    match result {
        ReplayOpenResult::Opened { session, events } => (session, events),
        ReplayOpenResult::RetentionGap { .. } => panic!("unexpected retention gap"),
    }
}
