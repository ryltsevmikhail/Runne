#[test]
fn v28_remains_a_released_schema_version() {
    assert_eq!(CURRENT_SCHEMA_VERSION, 29);
}

#[test]
fn v28_catalog_matches_the_applied_receipt_schema() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 28).unwrap();

    for name in V28_TRIGGERS {
        assert!(
            v24_trigger_matches(&connection, name, v28_trigger_source(name)).unwrap(),
            "missing or altered V28 trigger {name}"
        );
    }
    assert!(v28_predecessor_matches(&connection).unwrap());
    let receipt_table: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_credential_completion_receipts'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        normalize_v24_ddl(&receipt_table),
        v28_table_source("provider_credential_completion_receipts")
    );
    assert!(v28_operation_table_matches(&connection).unwrap());
    assert!(v28_trigger_catalog_matches(&connection).unwrap());
    let marker: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT MAX(version), MIN(version), COUNT(*), SUM(version) FROM schema_version",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert!(
        matches!(marker, (28, 1, 27, 387) | (28, 1, 28, 406)),
        "unexpected V28 marker: {marker:?}"
    );
    assert!(v28_matches(&connection, 28).unwrap());
}

#[test]
fn production_store_open_migrates_v28_to_v29() {
    let directory = tempfile::tempdir().unwrap();
    let created = directory.path().join("created-v28.sqlite");
    let connection = Connection::open(&created).unwrap();
    apply_migrations_internal(&connection, 28).unwrap();
    drop(connection);
    drop(crate::provider::SqliteProviderCredentialLifecycleStore::open(&created).unwrap());
    drop(crate::provider::SqliteProviderCredentialLifecycleStore::open(&created).unwrap());

    let migrated = directory.path().join("migrated-v28.sqlite");
    let connection = Connection::open(&migrated).unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 27).unwrap();
    drop(connection);
    drop(crate::provider::SqliteProviderCredentialLifecycleStore::open(&migrated).unwrap());
    drop(crate::provider::SqliteProviderCredentialLifecycleStore::open(&migrated).unwrap());
    let connection = Connection::open(&migrated).unwrap();
    assert_eq!(current_schema_marker(&connection), 29);
    assert!(v29_matches(&connection, 29).unwrap());
}

#[test]
fn production_store_open_rejects_tampered_v28_catalog_without_writing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("tampered-v28.sqlite");
    drop(crate::provider::SqliteProviderCredentialLifecycleStore::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_credential_completion_receipt_no_delete;")
        .unwrap();
    drop(connection);
    let before = std::fs::read(&path).unwrap();

    assert_eq!(
        crate::provider::SqliteProviderCredentialLifecycleStore::open(&path).err(),
        Some(runne_provider::CredentialLifecycleError::StoreUnavailable)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
