#[test]
fn v47_adds_durable_text_only_lineage_and_reopens() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 46).unwrap();
    assert_eq!(schema_marker(&connection), 46);
    assert!(v46_matches(&connection, 46).unwrap());

    apply_migrations(&connection).unwrap();
    assert_eq!(schema_marker(&connection), CURRENT_SCHEMA_VERSION);
    assert!(
        v69_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap(),
        "v46 inherited schema"
    );
    assert!(
        v47_triggers_match(&connection).unwrap(),
        "v47 trigger definitions"
    );
    assert!(v47_rows_match(&connection).unwrap(), "v47 lineage rows");
    assert!(v69_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap());
    assert!(classify_existing_connection(&connection).is_ok());

    let transaction = connection.unchecked_transaction().unwrap();
    transaction
        .execute(
            "INSERT INTO text_only_taskrun_lineage
             (taskrun_id, conversation_id, workspace_id, principal_id,
              origin_command_id, origin_operation, context_scope)
             VALUES (?1, ?2, ?3, 'test-owner', ?4, 18, 'text_only')",
            rusqlite::params![[0x11u8; 16], [0x22u8; 16], [0x33u8; 16], [0x44u8; 16]],
        )
        .unwrap();
    assert!(
        transaction
            .execute(
                "UPDATE text_only_taskrun_lineage SET principal_id='changed'",
                [],
            )
            .is_err()
    );
    assert!(
        transaction
            .execute("DELETE FROM text_only_taskrun_lineage", [])
            .is_err()
    );
    transaction.rollback().unwrap();

    connection
        .execute_batch("DROP TRIGGER text_only_taskrun_lineage_no_delete")
        .unwrap();
    assert!(!v69_matches(&connection, CURRENT_SCHEMA_VERSION).unwrap());
    assert!(!v47_matches(&connection, 47).unwrap());
    assert!(classify_existing_connection(&connection).is_err());
}
