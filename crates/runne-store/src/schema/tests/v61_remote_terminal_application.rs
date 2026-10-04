#[test]
fn v61_adds_append_only_remote_terminal_application_receipts() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 60).unwrap();
    apply_migrations_internal(&connection, 61).unwrap();
    assert_eq!(schema_marker(&connection), 61);
    assert!(
        v60_matches(&connection, 60).unwrap(),
        "predecessor v60 validator failed"
    );
    assert!(
        table_sql_matches_migration(
            &connection,
            "provider_remote_terminal_applications",
            MIGRATION_V61,
        )
        .unwrap(),
        "v61 table DDL differs from its migration"
    );
    assert!(
        v61_rows_match(&connection).unwrap(),
        "empty v61 receipt rows did not validate"
    );
    assert!(v61_matches(&connection, 61).unwrap());
    let ddl: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_remote_terminal_applications'",
        [], |row| row.get(0),
    ).unwrap();
    for required in [
        "accounting_state INTEGER NOT NULL CHECK(accounting_state IN (1,2))",
        "failure_reason TEXT NOT NULL",
        "FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_terminal_settlements",
        "CHECK((accounting_state=1 AND accounting_digest IS NOT NULL) OR (accounting_state=2 AND accounting_digest IS NULL))",
        "CHECK((conversation_terminal_event_id IS NULL)=(conversation_terminal_version IS NULL))",
        "conversation_observed_event_id BLOB NOT NULL",
    ] {
        assert!(
            ddl.contains(required),
            "missing application receipt contract: {required}"
        );
    }
}

#[test]
fn v61_reopen_readiness_rejects_removed_guards() {
    for trigger in [
        "provider_remote_terminal_applications_immutable",
        "provider_remote_terminal_applications_no_delete",
        "schema_v12_fence_provider_remote_terminal_applications_insert",
        "schema_v12_fence_provider_remote_terminal_applications_update",
        "schema_v12_fence_provider_remote_terminal_applications_delete",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 61).unwrap();
        connection
            .execute_batch(&format!("DROP TRIGGER {trigger}"))
            .unwrap();
        assert!(!v61_matches(&connection, 61).unwrap(), "{trigger}");
    }
}
