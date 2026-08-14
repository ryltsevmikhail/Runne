const V2_AUTHORITY: [u8; 16] = [0xAA; 16];
const V2_LINEAGE: [u8; 16] = [0xBB; 16];
const V2_SECRET: [u8; 32] = [0xCC; 32];

fn v2_event_id(position: i64) -> [u8; 16] {
    let mut id = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 0];
    id[14..].copy_from_slice(&u16::try_from(position).unwrap().to_be_bytes());
    id
}

fn insert_v2_event(connection: &Connection, sequence: i64, position: i64, id: [u8; 16]) {
    let taskrun = TaskRunId::from_bytes(id);
    let event_id = v2_event_id(position);
    let payload = match sequence {
        1 => TaskRunEvent::TaskRunCreated,
        2 => TaskRunEvent::TaskRunQueued,
        3 => TaskRunEvent::TaskRunAdmitted,
        4 => TaskRunEvent::AttemptStarted {
            attempt_id: gocode_domain::id::AttemptId::from_bytes(v2_event_id(4)),
        },
        value if value % 2 == 1 => TaskRunEvent::WaitStarted,
        _ => TaskRunEvent::Resumed,
    };
    let payload_bytes = TaskRunEventCodec.encode(&payload).unwrap();
    let key = IdempotencyKey::new(format!("v2-baseline-{position}")).unwrap();
    let causation = (position > 1).then(|| EventId::from_bytes(v2_event_id(position - 1)));
    let envelope = EventEnvelope::from_parts(
        EventId::from_bytes(event_id),
        AggregateId::TaskRun(taskrun),
        AggregateId::TaskRun(taskrun),
        causation,
        CommandId::from_bytes(event_id),
        key.clone(),
        1,
        Actor::new("v2-test").unwrap(),
        Sensitivity::Public,
        payload,
        sequence as u64,
        Timestamp::from_unix_micros(0),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_with_global_position(&envelope, position, &payload_bytes).unwrap();
    connection.execute(
        "INSERT INTO events (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version,
         causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile)
         VALUES (?1, 1, ?2, ?3, ?4, 0, 0, 1, ?5, ?1, ?6, ?7, ?8, ?9, ?2, 1, 1)",
        params![event_id.as_slice(), id.as_slice(), sequence, position, causation.map(|value| value.as_bytes().to_vec()), key.as_str().as_bytes(), b"v2-test".as_slice(), payload_bytes, digest.as_bytes().as_slice()],
    ).unwrap();
}

fn v2_test_facts(connection: &mut Connection) -> InternalResumeFacts {
    crate::schema::apply_migrations(connection).unwrap();
    let id = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 0xc1];
    connection.execute(
        "INSERT INTO aggregate_streams (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
         VALUES (1, ?1, 1, ?2, 0, 1)", params![id.as_slice(), v2_event_id(1).as_slice()],
    ).unwrap();
    insert_v2_event(connection, 1, 1, id);
    connection
        .execute(
            "UPDATE event_log_state SET next_global_position = 2 WHERE singleton = 1",
            [],
        )
        .unwrap();
    let snapshot_tx = connection.transaction().unwrap();
    crate::store::snapshot::refresh_aggregate_snapshot(&snapshot_tx, 1, &id).unwrap();
    snapshot_tx.commit().unwrap();
    let (promotion_projection_bytes, promotion_projection_digest): (Vec<u8>, [u8; 32]) = connection
        .query_row(
            "SELECT promotion_projection_bytes, promotion_projection_digest
             FROM aggregate_state_snapshots WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [id.as_slice()],
            |row| Ok((row.get(0)?, row.get::<_, Vec<u8>>(1)?.try_into().unwrap())),
        )
        .unwrap();
    InternalResumeFacts {
        principal_id: "principal".to_owned(),
        session_generation: 1,
        authority_id: V2_AUTHORITY,
        authorization_epoch: 7,
        aggregate_type: 1,
        aggregate_id: id,
        sequence: 1,
        version: 1,
        baseline_global_position: 1,
        head_event_id: v2_event_id(1),
        head_integrity_digest: {
            let mut statement = connection
                .prepare("SELECT integrity_digest FROM events WHERE global_position = 1")
                .unwrap();
            statement
                .query_row([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .try_into()
                .unwrap()
        },
        promotion_projection_bytes,
        promotion_projection_digest,
        retained_floor: 1,
        captured_high_water: 1,
        retention_generation: 1,
        retention_manifest_digest: baseline_resume_manifest_digest(
            &EventLogLineageId::from_bytes(V2_LINEAGE),
            0,
            1,
            &V2_SECRET,
        ),
    }
}

struct V2AllowDelivery;

impl ReplayDeliveryPrecommitGuard for V2AllowDelivery {
    fn inspect(&self, _: &ReplaySession, _: &[ReplayEvent]) -> Result<(), ReplayError> {
        Ok(())
    }
}

fn assert_v2_rejected(connection: &mut Connection, facts: InternalResumeFacts) {
    assert!(
        resume_session_from_internal_facts(
            connection,
            facts,
            &EventLogLineageId::from_bytes(V2_LINEAGE),
            &V2_SECRET,
            Arc::new(V2AllowDelivery),
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

#[test]
fn v2_store_admission_resumes_after_historical_baseline_in_page_sizes() {
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
        let (session, events, _, _) = resume_session_from_internal_facts(
            &mut connection,
            facts,
            &EventLogLineageId::from_bytes(V2_LINEAGE),
            &V2_SECRET,
            Arc::new(V2AllowDelivery),
        )
        .unwrap();
        assert_eq!(
            events.len(),
            usize::try_from(suffix_count.min(100)).unwrap()
        );
        assert!(events.iter().all(|event| event.sequence > 1));
        assert_eq!(session.last_acked_position, Some(1));
        assert_eq!(
            session.last_delivered_position,
            Some(suffix_count.min(100) + 1)
        );
        assert_eq!(
            session.next_page_position,
            (suffix_count > 100).then_some(102)
        );
        assert!(!session.created_at.is_empty());
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            1
        );
    }
}

#[test]
fn v2_store_admission_rejects_historical_head_manifest_and_pruning_mutations() {
    for mutation in [0, 1, 2, 3, 4, 5, 6, 7] {
        let mut connection = Connection::open_in_memory().unwrap();
        let mut facts = v2_test_facts(&mut connection);
        match mutation {
            0 => facts.head_event_id[15] ^= 1,
            1 => facts.head_integrity_digest[0] ^= 1,
            2 => facts.baseline_global_position = 2,
            3 => facts.retention_manifest_digest[0] ^= 1,
            4 => {
                connection
                    .execute("DELETE FROM events WHERE global_position = 1", [])
                    .unwrap();
            }
            _ => {
                if mutation == 6 {
                    connection
                        .execute(
                            "UPDATE aggregate_streams SET current_version = 2 WHERE aggregate_type = 1",
                            [],
                        )
                        .unwrap();
                } else {
                    connection
                        .execute(
                            "UPDATE event_log_state SET next_global_position = 3 WHERE singleton = 1",
                            [],
                        )
                        .unwrap();
                }
            }
        }
        assert_v2_rejected(&mut connection, facts);
    }
}

#[test]
fn v2_store_admission_rejects_pruned_floor_and_retained_suffix_gap() {
    let mut pruned = Connection::open_in_memory().unwrap();
    let facts = v2_test_facts(&mut pruned);
    pruned
        .execute("DELETE FROM events WHERE global_position = 1", [])
        .unwrap();
    assert_v2_rejected(&mut pruned, facts);

    let mut gapped = Connection::open_in_memory().unwrap();
    let facts = v2_test_facts(&mut gapped);
    insert_v2_event(&gapped, 2, 2, facts.aggregate_id);
    insert_v2_event(&gapped, 3, 3, facts.aggregate_id);
    gapped
        .execute("DELETE FROM events WHERE global_position = 2", [])
        .unwrap();
    assert_v2_rejected(&mut gapped, facts);
}
