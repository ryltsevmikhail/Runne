fn v2_ack_cursor(event: &ReplayEvent, aggregate_id: [u8; 16]) -> ReplayCursor {
    ReplayCursor {
        event_id: EventId::from_bytes(event.event_id),
        aggregate_id: AggregateId::TaskRun(TaskRunId::from_bytes(aggregate_id)),
        sequence: u64::try_from(event.sequence).unwrap(),
        global_position: event.global_position,
        lineage_id: EventLogLineageId::from_bytes(V2_LINEAGE),
        scope: ReplayScope::Aggregate {
            aggregate_type: 1,
            aggregate_id,
        },
        schema_version: gocode_domain::replay::CURSOR_SCHEMA_VERSION,
        sensitivity: Sensitivity::Public,
        event_type: event.event_type.clone(),
        integrity: IntegrityDigest::from_bytes([0; 32]),
    }
}

#[tokio::test]
async fn v2_resumed_sessions_page_ack_and_complete_each_suffix_once() {
    for suffix_count in [0_i64, 1, 100, 101] {
        let mut connection = Connection::open_in_memory().unwrap();
        let facts = v2_test_facts(&mut connection);
        for position in 2..=suffix_count + 1 {
            insert_v2_event(&connection, position, position, facts.aggregate_id);
        }
        if suffix_count > 0 {
            connection.execute(
                "UPDATE aggregate_streams SET current_version = ?1, last_event_id = ?2, last_timestamp = 0 WHERE aggregate_type = 1",
                params![suffix_count + 1, v2_event_id(suffix_count + 1).as_slice()],
            ).unwrap();
            let snapshot_tx = connection.transaction().unwrap();
            crate::store::snapshot::refresh_aggregate_snapshot(
                &snapshot_tx,
                1,
                &facts.aggregate_id,
            )
            .unwrap();
            snapshot_tx.commit().unwrap();
        }
        connection
            .execute(
                "UPDATE event_log_state SET next_global_position = ?1 WHERE singleton = 1",
                [suffix_count + 2],
            )
            .unwrap();
        let (mut session, mut delivered, _, _) = resume_session_from_internal_facts(
            &mut connection,
            facts.clone(),
            &EventLogLineageId::from_bytes(V2_LINEAGE),
            &V2_SECRET,
            Arc::new(V2AllowDelivery),
        )
        .unwrap();
        let store = ReplayStore::new(connection);
        let (paged, page) = store
            .read_page(
                &session.session_id,
                &facts.principal_id,
                facts.session_generation,
                &facts.authority_id,
                facts.authorization_epoch,
                100,
                Arc::new(V2AllowDelivery),
            )
            .await
            .unwrap();
        session = paged;
        delivered.extend(page);

        let positions = delivered
            .iter()
            .map(|event| event.global_position)
            .collect::<Vec<_>>();
        assert_eq!(positions, (2..=suffix_count + 1).collect::<Vec<_>>());
        assert_eq!(session.last_delivered_position, Some(suffix_count + 1));
        assert_eq!(session.next_page_position, None);
        assert!(!session.created_at.is_empty());
        if let Some(event) = delivered.last() {
            store
                .acknowledge(
                    &session.session_id,
                    &facts.principal_id,
                    facts.session_generation,
                    &facts.authority_id,
                    facts.authorization_epoch,
                    &v2_ack_cursor(event, facts.aggregate_id),
                    Arc::new(V2AllowDelivery),
                )
                .await
                .unwrap();
        }
        let (completed, last_acked) = store
            .complete_catch_up(
                &session.session_id,
                &facts.principal_id,
                facts.session_generation,
                &facts.authority_id,
                facts.authorization_epoch,
                &V2_SECRET,
                Arc::new(V2AllowDelivery),
            )
            .await
            .unwrap();
        assert_eq!(completed.state, ReplayState::CatchUpComplete);
        assert!(completed.catch_up_completion.is_some());
        assert_eq!(last_acked.unwrap().global_position, suffix_count + 1);
        let connection = store.conn.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM _replay_subscriptions WHERE session_id = ?1",
                    [session.session_id.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }
}
