type StoredReplayTuple = ([u8; 16], [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

fn assert_v35_original_survives_replay_conflict(identity: usize) {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA recursive_triggers", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
    seed_v35_ticket(&connection, 60, 1);
    let original = V35FenceInsert::valid(60, 70);
    insert_v35_fence(&connection, &original).unwrap();

    let replay = if identity == 0 {
        V35FenceInsert::valid(60, 90)
    } else {
        seed_v35_ticket(&connection, 61, 1);
        let mut value = V35FenceInsert::valid(61, 90);
        value.replay_ids[identity - 1] = original.replay_ids[identity - 1];
        value
    };
    assert!(insert_v35_fence(&connection, &replay).is_err());
    assert!(replace_v35_fence(&connection, &replay).is_err());

    let stored: StoredReplayTuple = connection
        .query_row(
            "SELECT operation_id,context_id,context_nonce,ticket_id,ticket_nonce
             FROM provider_qualification_admission_fences",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .unwrap();
    assert_eq!(stored.0, [60; 16]);
    assert_eq!(stored.1, original.replay_ids[0]);
    assert_eq!(stored.2, original.replay_ids[1]);
    assert_eq!(stored.3, original.replay_ids[2]);
    assert_eq!(stored.4, original.replay_ids[3]);
}

#[test]
fn v35_rejects_insert_and_replace_for_each_replay_identity() {
    for identity in 0..=4 {
        assert_v35_original_survives_replay_conflict(identity);
    }
}

fn replace_v35_table_with_case_mutation(connection: &Connection, from: &str, to: &str) {
    let table: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [V35_TABLE],
            |row| row.get(0),
        )
        .unwrap();
    let triggers: Vec<String> = connection
        .prepare(
            "SELECT sql FROM sqlite_master
             WHERE type='trigger' AND tbl_name=?1 ORDER BY name",
        )
        .unwrap()
        .query_map([V35_TABLE], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    connection
        .execute_batch(&format!(
            "DROP TABLE {V35_TABLE}; {}",
            table.replace(from, to)
        ))
        .unwrap();
    for trigger in triggers {
        connection.execute_batch(&trigger).unwrap();
    }
}

#[test]
fn v35_classification_and_managed_reopen_reject_case_changed_literals() {
    for (from, to) in [
        ("'macos-xpc-dpk-v1'", "'MACOS-XPC-DPK-V1'"),
        ("'service'", "'SERVICE'"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = { let daemon = directory.path().join("runne-daemon"); std::fs::create_dir_all(&daemon).unwrap(); daemon.join("case-mutated-v35.sqlite") };
        let connection = Connection::open(&path).unwrap();
        apply_migrations(&connection).unwrap();
        replace_v35_table_with_case_mutation(&connection, from, to);
        assert!(!v35_matches(&connection, 35).unwrap());
        assert!(classify_existing_connection(&connection).is_err());
        drop(connection);
        assert!(open_managed_connection(&path, ConnectionMode::Writer).is_err());
    }
}
