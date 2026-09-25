#[test]
fn taskrun_claim_migration_from_v41_survives_close_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("claim-v42.sqlite");
    let connection = Connection::open(&path).unwrap();
    apply_migrations_internal(&connection, 41).unwrap();
    assert!(v41_matches(&connection, 41).unwrap());

    apply_migrations(&connection).unwrap();
    assert_eq!(schema_marker(&connection), 44);
    assert!(v43_matches(&connection, 43).unwrap());
    drop(connection);

    let reopened = Connection::open(&path).unwrap();
    assert!(v43_matches(&reopened, 43).unwrap());
    assert_eq!(schema_marker(&reopened), CURRENT_SCHEMA_VERSION);
}

#[test]
fn v42_rejects_missing_global_command_id_triggers() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 42).unwrap();
    assert!(v42_matches(&connection, 42).unwrap());
    connection
        .execute_batch("DROP TRIGGER global_command_id_from_project_workspace_receipts_v42;")
        .unwrap();
    assert!(!v42_matches(&connection, 42).unwrap());
}
