struct V2RejectEvent;

impl ReplayDeliveryPrecommitGuard for V2RejectEvent {
    fn inspect(&self, _: &ReplaySession, _: &[ReplayEvent]) -> Result<(), ReplayError> {
        Ok(())
    }

    fn inspect_event(&self, _: &ReplaySession, _: &ReplayEvent) -> Result<(), ReplayError> {
        Err(ReplayError::SensitivityDenied)
    }
}

#[test]
fn v2_store_admission_delegate_event_rejection_inserts_zero_rows() {
    let mut connection = Connection::open_in_memory().unwrap();
    let facts = v2_test_facts(&mut connection);
    insert_v2_event(&connection, 2, 2, facts.aggregate_id);
    connection.execute(
        "UPDATE aggregate_streams SET current_version = 2, last_event_id = ?1, last_timestamp = 0 WHERE aggregate_type = 1",
        [v2_event_id(2).as_slice()],
    ).unwrap();
    let snapshot_tx = connection.transaction().unwrap();
    crate::store::snapshot::refresh_aggregate_snapshot(&snapshot_tx, 1, &facts.aggregate_id)
        .unwrap();
    snapshot_tx.commit().unwrap();
    connection
        .execute(
            "UPDATE event_log_state SET next_global_position = 3 WHERE singleton = 1",
            [],
        )
        .unwrap();
    assert!(
        resume_session_from_internal_facts(
            &mut connection,
            facts,
            &EventLogLineageId::from_bytes(V2_LINEAGE),
            &V2_SECRET,
            Arc::new(V2RejectEvent),
        )
        .is_err()
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
}
