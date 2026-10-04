#[test]
fn v57_installs_append_only_successor_lineage_and_preserves_v56() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 56).unwrap();
    assert!(v56_matches(&connection, 56).unwrap());
    apply_migrations_internal(&connection, 57).unwrap();
    assert_eq!(schema_marker(&connection), 57);
    assert!(v56_matches(&connection, 57).unwrap());
    assert!(v57_matches(&connection, 57).unwrap());
    let ddl: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='taskrun_unknown_successor_receipts'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    for required in [
        "predecessor_taskrun_id BLOB PRIMARY KEY",
        "successor_taskrun_id BLOB NOT NULL UNIQUE",
        "acknowledgement_code='duplicate_execution_and_cost_v1'",
        "CHECK((predecessor_event_id IS NULL)=(predecessor_event_version IS NULL))",
    ] {
        assert!(ddl.contains(required), "missing DDL contract: {required}");
    }
}

#[test]
fn v57_readiness_rejects_missing_guards_and_orphan_successor_rows() {
    for trigger in [
        "taskrun_unknown_successor_receipts_immutable",
        "taskrun_unknown_successor_receipts_no_delete",
        "schema_v12_fence_taskrun_unknown_successor_receipts_insert",
        "schema_v12_fence_taskrun_unknown_successor_receipts_update",
        "schema_v12_fence_taskrun_unknown_successor_receipts_delete",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 57).unwrap();
        connection
            .execute_batch(&format!("DROP TRIGGER {trigger}"))
            .unwrap();
        assert!(!v57_matches(&connection, 57).unwrap(), "{trigger}");
    }
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 57).unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute(
            "INSERT INTO taskrun_unknown_successor_receipts (
               predecessor_taskrun_id,successor_taskrun_id,predecessor_attempt_id,
               conversation_id,successor_submit_event_id,successor_submit_version,workspace_id,
               principal_digest,principal_id,origin_kind,project_id,origin_operation,
               acknowledgement_code,acknowledgement_version,acknowledgement_digest,
               predecessor_input_digest,typed_input_digest,occupation_fence,
               occupation_release_event_id,occupation_release_version,occupation_release_reason,
               command_id,idempotency_key_digest,command_fingerprint,created_at
             ) VALUES (?1,?2,?3,?4,?5,1,?6,?7,'diagnostic','canonical_workspace',?8,24,'duplicate_execution_and_cost_v1',1,?9,?10,?11,1,?12,1,'user_supersession',?13,?14,?15,0)",
            rusqlite::params![
                [1_u8; 16], [2_u8; 16], [3_u8; 16], [4_u8; 16], [5_u8; 16], [6_u8; 16],
                [7_u8; 32], [8_u8; 16], [9_u8; 32], [10_u8; 32], [11_u8; 32],
                [12_u8; 16], [13_u8; 16], [14_u8; 32], [15_u8; 32],
            ],
        )
        .unwrap();
    assert!(!v57_matches(&connection, 57).unwrap());
}
