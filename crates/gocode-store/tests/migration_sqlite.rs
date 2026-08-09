#[path = "support/validated_reopen.rs"]
mod validated_reopen;

include!("migration_sqlite_split_parts/part_01.rs");
include!("migration_sqlite_split_parts/part_02.rs");
include!("migration_sqlite_split_parts/part_03.rs");
include!("migration_sqlite_split_parts/part_04.rs");
include!("migration_sqlite_split_parts/part_05.rs");
include!("migration_sqlite_split_parts/part_06.rs");

#[test]
fn interrupted_v17_migration_recovers_on_reopen() {
    use gocode_store::{
        provider::SqliteProviderExecutionStore,
        schema::{ConnectionMode, apply_migrations, open_managed_connection},
    };

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("interrupted-v17.sqlite");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch(
            "DROP INDEX IF EXISTS bootstrap_reservation_unexpired;
             DROP TABLE IF EXISTS bootstrap_reservation_tombstones;
             DROP TABLE IF EXISTS bootstrap_reservations;
             DROP TABLE IF EXISTS bootstrap_last_observed_clock;
             DELETE FROM schema_version WHERE version = 17;",
        )
        .unwrap();
    {
        let interrupted = connection.unchecked_transaction().unwrap();
        interrupted
            .execute_batch(
                "CREATE TABLE bootstrap_reservations (
                    reservation_key BLOB PRIMARY KEY,
                    challenge_id BLOB NOT NULL
                 );",
            )
            .unwrap();
    }
    assert!(!connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='bootstrap_reservations')",
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
        17
    );
    assert_eq!(
        reopened
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('bootstrap_reservations')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        16
    );
}
