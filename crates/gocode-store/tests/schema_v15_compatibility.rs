use std::path::{Path, PathBuf};

use gocode_store::{
    provider::SqliteProviderExecutionStore,
    schema::{
        CURRENT_SCHEMA_VERSION, ConnectionMode, apply_migrations, open_managed_connection,
        preflight_existing_file,
    },
};
use rusqlite::{Connection, params};

fn released_v15_database() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("released-v15.sqlite");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER IF EXISTS provider_credential_transition_order;
             DROP TRIGGER IF EXISTS provider_credential_identity_immutable;
             DROP TRIGGER IF EXISTS provider_credential_insert_prepared;
             DROP TRIGGER IF EXISTS provider_credential_tombstone_permanent;
             DROP INDEX IF EXISTS provider_credential_one_active;
             DROP TABLE IF EXISTS provider_credential_versions;
             DELETE FROM schema_version WHERE version = 16;",
        )
        .unwrap();
    drop(connection);
    (directory, path)
}

fn replace_table_ddl(path: &Path, table: &str, old: &str, new: &str) {
    let connection = Connection::open(path).unwrap();
    let ddl: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .unwrap();
    assert!(ddl.contains(old), "fixture did not find {old:?} in {table}");
    let cookie: i64 = connection
        .pragma_query_value(None, "schema_version", |row| row.get(0))
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema = ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE sqlite_master SET sql = replace(sql, ?2, ?3)
             WHERE type = 'table' AND name = ?1",
            params![table, old, new],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema = OFF;")
        .unwrap();
    connection
        .execute_batch(&format!("PRAGMA schema_version = {};", cookie + 1))
        .unwrap();
}

#[test]
fn preflight_rejects_v15_with_tampered_inherited_v14_activation_binding() {
    let (_directory, path) = released_v15_database();
    replace_table_ddl(
        &path,
        "provider_execution_admissions",
        "activation_binding_kind TEXT NOT NULL DEFAULT 'legacy_unbound'\n    CHECK(activation_binding_kind IN ('legacy_unbound', 'protected_v2', 'external_owner_private'))",
        "activation_binding_kind TEXT NOT NULL DEFAULT 'legacy_unbound'",
    );
    assert!(preflight_existing_file(&path).is_err());
    assert!(SqliteProviderExecutionStore::open(&path).is_err());
}

#[test]
fn preflight_accepts_released_v15_shape() {
    let (_directory, path) = released_v15_database();
    preflight_existing_file(&path).unwrap();
    SqliteProviderExecutionStore::open(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    assert_eq!(CURRENT_SCHEMA_VERSION, 16);
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    assert!(connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'provider_effect_starts')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap());
}

#[test]
fn v15_to_v16_catalog_reopens_after_restart() {
    let (_directory, path) = released_v15_database();
    preflight_existing_file(&path).unwrap();

    drop(SqliteProviderExecutionStore::open(&path).unwrap());
    preflight_existing_file(&path).unwrap();
    drop(SqliteProviderExecutionStore::open(&path).unwrap());

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        16
    );
    assert!(connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'provider_credential_versions')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap());
}

#[test]
fn corrupt_v16_catalog_is_rejected_before_open() {
    let (_directory, path) = released_v15_database();
    drop(SqliteProviderExecutionStore::open(&path).unwrap());
    replace_table_ddl(
        &path,
        "provider_credential_versions",
        "CHECK(length(ref_digest) = 32)",
        "CHECK(length(ref_digest) <= 32)",
    );

    assert!(preflight_existing_file(&path).is_err());
    assert!(SqliteProviderExecutionStore::open(&path).is_err());
}
