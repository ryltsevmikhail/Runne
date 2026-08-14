include!("migration_routing_sqlite/scenarios.rs");
include!("migration_routing_sqlite/support.rs");

#[test]
fn corrupt_v16_or_v17_catalog_is_rejected_before_open() {
    use gocode_store::schema::{
        ConnectionMode, apply_migrations, open_managed_connection, preflight_existing_file,
    };

    let directory = tempfile::tempdir().unwrap();
    let v17 = directory.path().join("corrupt-v17.sqlite");
    let connection = open_managed_connection(&v17, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch("DROP TABLE bootstrap_reservation_tombstones;")
        .unwrap();
    drop(connection);
    assert!(preflight_existing_file(&v17).is_err());

    let v16 = directory.path().join("corrupt-v16.sqlite");
    let connection = open_managed_connection(&v16, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch(
            "DROP INDEX IF EXISTS bootstrap_reservation_unexpired;
             DROP TABLE IF EXISTS bootstrap_reservation_tombstones;
             DROP TABLE IF EXISTS bootstrap_reservations;
             DROP TABLE IF EXISTS bootstrap_last_observed_clock;
             DELETE FROM schema_version WHERE version = 17;
             DROP TABLE provider_credential_effect_bindings;",
        )
        .unwrap();
    drop(connection);
    assert!(preflight_existing_file(&v16).is_err());
}
