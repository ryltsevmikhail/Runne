#[test]
fn v53_local_stop_receipt_migrates_after_frozen_v52_and_checks_guards() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 52).unwrap();
    assert_eq!(schema_marker(&connection), 52);
    assert!(v52_matches(&connection, 52).unwrap());

    apply_migrations_internal(&connection, 53).unwrap();
    assert_eq!(schema_marker(&connection), 53);
    assert!(v53_matches(&connection, 53).unwrap());
    let ddl: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='taskrun_local_command_stop_receipts'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(ddl.contains("PRIMARY KEY(taskrun_id,fence)"));
    assert!(ddl.contains("UNIQUE(taskrun_id,attempt_id)"));
    assert!(ddl.contains("proof_node_epoch>historic_node_epoch"));

    for trigger in [
        "taskrun_local_command_stop_receipts_immutable",
        "taskrun_local_command_stop_receipts_no_delete",
        "schema_v12_fence_taskrun_local_command_stop_receipts_insert",
        "schema_v12_fence_taskrun_local_command_stop_receipts_update",
        "schema_v12_fence_taskrun_local_command_stop_receipts_delete",
    ] {
        let drifted = Connection::open_in_memory().unwrap();
        apply_migrations(&drifted).unwrap();
        drifted
            .execute_batch(&format!("DROP TRIGGER {trigger};"))
            .unwrap();
        assert!(
            !v53_matches(&drifted, 53).unwrap(),
            "readiness must reject missing trigger {trigger}"
        );
    }
}

#[test]
fn v53_local_stop_receipt_constraints_reject_invalid_identity_and_epoch() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    let insert = "INSERT INTO taskrun_local_command_stop_receipts
        (taskrun_id,fence,attempt_id,historic_node_id,historic_node_epoch,
         proof_node_id,proof_node_epoch,managed_area_identity,command_digest,
         stop_kind,terminal_event_id,terminal_version)
        VALUES (?1,1,?2,?3,2,?4,?5,?6,?7,'outcome_unknown',?8,6)";
    let area = [8_u8; 100];
    let digest = [9_u8; 32];
    assert!(
        connection
            .execute(
                insert,
                rusqlite::params![
                    [1_u8; 16], [2_u8; 16], [3_u8; 16], [3_u8; 16], 2, area, digest, [4_u8; 16]
                ],
            )
            .is_err(),
        "proof epoch must be newer"
    );
    assert!(
        connection
            .execute(
                insert,
                rusqlite::params![
                    [1_u8; 16], [2_u8; 16], [3_u8; 16], [4_u8; 16], 3, area, digest, [5_u8; 16]
                ],
            )
            .is_err(),
        "proof owner must be the historical node"
    );
    assert!(
        connection
            .execute(
                insert,
                rusqlite::params![
                    [0_u8; 16], [2_u8; 16], [3_u8; 16], [3_u8; 16], 3, area, digest, [6_u8; 16]
                ],
            )
            .is_err(),
        "taskrun identity cannot be zero"
    );
    assert!(
        connection
            .execute(
                insert,
                rusqlite::params![
                    [1_u8; 16], [2_u8; 16], [3_u8; 16], [3_u8; 16], 3, area, [0_u8; 32], [7_u8; 16]
                ],
            )
            .is_err(),
        "command digest cannot be zero"
    );
}

#[test]
fn managed_v53_store_rejects_orphan_stop_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    let path = daemon.join("v53-orphan.sqlite");
    let managed = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&managed).unwrap();
    drop(managed);
    let raw = Connection::open(&path).unwrap();
    assert_eq!(schema_marker(&raw), CURRENT_SCHEMA_VERSION);
    assert!(v63_matches(&raw, CURRENT_SCHEMA_VERSION).unwrap());
    drop(raw);
    drop(open_managed_connection(&path, ConnectionMode::Writer).unwrap());

    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    raw.execute(
        "INSERT INTO taskrun_local_command_stop_receipts
         (taskrun_id,fence,attempt_id,historic_node_id,historic_node_epoch,
          proof_node_id,proof_node_epoch,managed_area_identity,command_digest,
          stop_kind,terminal_event_id,terminal_version)
         VALUES (?1,1,?2,?3,2,?3,3,?4,?5,'outcome_unknown',?6,6)",
        rusqlite::params![
            [1_u8; 16],
            [2_u8; 16],
            [3_u8; 16],
            [4_u8; 100],
            [5_u8; 32],
            [6_u8; 16]
        ],
    )
    .unwrap();
    drop(raw);
    assert!(
        open_managed_connection(&path, ConnectionMode::Writer).is_err(),
        "managed admission must reject a receipt without origin, terminal and occupation proof"
    );
}
