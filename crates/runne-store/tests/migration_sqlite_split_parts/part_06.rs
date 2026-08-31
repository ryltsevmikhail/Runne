#[test]
fn interrupted_v16_migration_recovers_on_reopen() {
    use runne_store::{
        provider::SqliteProviderExecutionStore,
        schema::{
            CURRENT_SCHEMA_VERSION, ConnectionMode, apply_migrations_through_v15_for_test,
            open_managed_connection,
        },
    };

    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon.join("interrupted-v16.sqlite");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations_through_v15_for_test(&connection).unwrap();
    {
        let interrupted = connection.unchecked_transaction().unwrap();
        interrupted
            .execute_batch(
                "CREATE TABLE provider_credential_versions (
                    provider_id TEXT NOT NULL,
                    credential_version INTEGER NOT NULL
                 );",
            )
            .unwrap();
    }
    assert!(!connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='provider_credential_versions')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap());
    drop(connection);

    drop(SqliteProviderExecutionStore::open(&path).unwrap());
    let reopened = Connection::open(&path).unwrap();
    assert_eq!(
        reopened
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        reopened
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('provider_credential_versions')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        9
    );
}
