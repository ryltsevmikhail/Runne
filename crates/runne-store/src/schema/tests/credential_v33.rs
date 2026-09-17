#[test]
fn v35_preserves_v33_admission_and_rejects_old_completion_guard_after_upgrade() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 33).unwrap();
    assert!(v33_matches(&connection, 33).unwrap());
    apply_migrations(&connection).unwrap();
    assert!(v37_matches(&connection, 37).unwrap());
    connection.execute_batch("DROP TRIGGER provider_credential_completion_receipt_insert").unwrap();
    connection.execute_batch(v28_trigger_source("provider_credential_completion_receipt_insert")).unwrap();
    assert!(!project_workspace_schema::v36_matches(&connection, 36).unwrap());
    assert!(apply_migrations(&connection).is_err());
}

#[test]
fn v33_managed_reopen_rejects_missing_recovery_uniqueness_guard() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("cleanup-recovery.sqlite");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let guard_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'credential_cleanup_recovery_one_live')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(guard_exists, "recovery must have a durable one-live-attempt guard");
    drop(connection);

    // A valid database must reopen before corruption is introduced, so an
    // unrelated path/profile failure cannot satisfy the rejection assertion.
    drop(open_managed_connection(&path, ConnectionMode::Writer).unwrap());
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("DROP INDEX credential_cleanup_recovery_one_live")
        .unwrap();
    drop(raw);

    assert!(
        open_managed_connection(&path, ConnectionMode::Writer).is_err(),
        "managed admission must reject a missing recovery concurrency guard"
    );
}

#[test]
fn v33_upgrade_is_idempotent_and_preserves_v32_exact_catalog() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 32).unwrap();
    assert!(v32_matches(&connection, 32).unwrap());
    connection.execute_batch("CREATE TABLE unexpected_recovery (id INTEGER)").unwrap();
    assert!(!v32_matches(&connection, 32).unwrap());
    assert!(apply_migrations(&connection).is_err());
    connection.execute_batch("DROP TABLE unexpected_recovery").unwrap();
    apply_migrations(&connection).unwrap();
    assert!(v37_matches(&connection, 37).unwrap());
    apply_migrations(&connection).unwrap();
    assert!(v37_matches(&connection, 37).unwrap());
}

#[test]
fn v33_rejects_replaced_trigger_and_extra_catalog_object() {
    for mutation in [
        "DROP TRIGGER credential_cleanup_recovery_immutable; CREATE TRIGGER credential_cleanup_recovery_immutable BEFORE UPDATE ON credential_cleanup_recovery_attempts BEGIN SELECT 1; END;",
        "CREATE INDEX unexpected_recovery_index ON credential_cleanup_recovery_attempts(state)",
        "CREATE TABLE unexpected_recovery_table (id INTEGER)",
        "ALTER TABLE provider_credential_process_attachments ADD COLUMN unexpected_authority INTEGER",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations(&connection).unwrap();
        assert!(v37_matches(&connection, 37).unwrap());
        connection.execute_batch(mutation).unwrap();
        assert!(!project_workspace_schema::v36_matches(&connection, 36).unwrap(), "{mutation}");
        assert!(apply_migrations(&connection).is_err(), "{mutation}");
    }
}
