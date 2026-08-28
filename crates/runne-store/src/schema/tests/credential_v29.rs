#[test]
fn v29_remains_a_released_schema_boundary() {
    assert_eq!(CURRENT_SCHEMA_VERSION, 30);
}

#[test]
fn v29_catalog_preserves_the_append_only_attachment_boundary() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 29).unwrap();

    assert!(v29_predecessor_matches(&connection).unwrap());
    assert!(v29_catalog_matches(&connection).unwrap());
    let table: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [V29_TABLE],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(normalize_v24_ddl(&table), v29_table_source());
    for name in V29_TRIGGERS {
        assert!(
            v24_trigger_matches(&connection, name, v29_trigger_source(name)).unwrap(),
            "missing or altered V29 trigger {name}"
        );
    }
    let marker: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT MAX(version), MIN(version), COUNT(*), SUM(version) FROM schema_version",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(marker, (29, 1, 28, 416));
    assert!(v29_matches(&connection, 29).unwrap());
}

#[test]
fn production_store_open_creates_and_reopens_v30() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("created-v29.sqlite");

    drop(crate::provider::SqliteProviderCredentialLifecycleStore::open(&path).unwrap());
    drop(crate::provider::SqliteProviderCredentialLifecycleStore::open(&path).unwrap());

    let connection = Connection::open(path).unwrap();
    assert!(v30_matches(&connection, 30).unwrap());
}
