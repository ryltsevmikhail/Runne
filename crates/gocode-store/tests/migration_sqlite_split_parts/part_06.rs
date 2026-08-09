#[test]
fn interrupted_v16_migration_recovers_on_reopen() {
    use gocode_store::{
        provider::SqliteProviderExecutionStore,
        schema::{ConnectionMode, apply_migrations, open_managed_connection},
    };

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("interrupted-v16.sqlite");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER IF EXISTS provider_credential_transition_order;
             DROP TRIGGER IF EXISTS provider_credential_identity_immutable;
             DROP TRIGGER IF EXISTS provider_credential_insert_prepared;
             DROP TRIGGER IF EXISTS provider_credential_tombstone_permanent;
             DROP INDEX IF EXISTS provider_credential_one_active;
             DROP TABLE IF EXISTS provider_credential_effect_bindings;
             DROP TABLE IF EXISTS provider_credential_versions;
             DELETE FROM schema_version WHERE version = 16;",
        )
        .unwrap();
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
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        16
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
