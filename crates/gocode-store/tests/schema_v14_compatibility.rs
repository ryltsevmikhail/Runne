use std::path::{Path, PathBuf};

use gocode_store::{
    provider::SqliteProviderExecutionStore,
    schema::{ConnectionMode, apply_migrations, open_managed_connection, preflight_existing_file},
};
use rusqlite::{Connection, params};

fn released_v14_database(name: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(format!("{name}.sqlite"));
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
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

fn rejects_after_ddl_replacement(table: &str, old: &str, new: &str) {
    let (_directory, path) = released_v14_database("malformed-v14");
    replace_table_ddl(&path, table, old, new);
    assert!(
        preflight_existing_file(&path).is_err(),
        "preflight accepted malformed {table}: {old:?} -> {new:?}"
    );
    assert!(SqliteProviderExecutionStore::open(&path).is_err());
}

#[test]
fn preflight_rejects_v14_added_columns_without_exact_not_null_type_and_default() {
    for (table, old, new) in [
        (
            "provider_runtime_authority_state",
            "capability_expires_at INTEGER NOT NULL DEFAULT 0",
            "capability_expires_at INTEGER DEFAULT 0",
        ),
        (
            "provider_runtime_authority_state",
            "capability_revocation_epoch INTEGER NOT NULL DEFAULT 0",
            "capability_revocation_epoch TEXT NOT NULL DEFAULT 0",
        ),
        (
            "provider_runtime_authority_state",
            "capability_revocation_observed INTEGER NOT NULL DEFAULT 0",
            "capability_revocation_observed INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "provider_runtime_authority_state",
            "approval_revocation_epoch INTEGER NOT NULL DEFAULT 0",
            "approval_revocation_epoch INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "provider_runtime_authority_state",
            "approval_revocation_observed INTEGER NOT NULL DEFAULT 0",
            "approval_revocation_observed TEXT NOT NULL DEFAULT 0",
        ),
        (
            "provider_execution_admissions",
            "owner_id TEXT NOT NULL DEFAULT ''",
            "owner_id TEXT DEFAULT ''",
        ),
        (
            "provider_execution_admissions",
            "scope TEXT NOT NULL DEFAULT ''",
            "scope BLOB NOT NULL DEFAULT ''",
        ),
        (
            "provider_execution_admissions",
            "capability_revision INTEGER NOT NULL DEFAULT 0",
            "capability_revision INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "provider_execution_admissions",
            "capability_expires_at INTEGER NOT NULL DEFAULT 0",
            "capability_expires_at TEXT NOT NULL DEFAULT 0",
        ),
        (
            "provider_execution_admissions",
            "capability_revocation_observed INTEGER NOT NULL DEFAULT 0",
            "capability_revocation_observed INTEGER DEFAULT 0",
        ),
        (
            "provider_execution_admissions",
            "approval_id TEXT NOT NULL DEFAULT ''",
            "approval_id TEXT DEFAULT ''",
        ),
        (
            "provider_execution_admissions",
            "approval_revision INTEGER NOT NULL DEFAULT 0",
            "approval_revision INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "provider_execution_admissions",
            "approval_expires_at INTEGER NOT NULL DEFAULT 0",
            "approval_expires_at TEXT NOT NULL DEFAULT 0",
        ),
        (
            "provider_execution_admissions",
            "approval_revocation_epoch INTEGER NOT NULL DEFAULT 0",
            "approval_revocation_epoch INTEGER DEFAULT 0",
        ),
        (
            "provider_execution_admissions",
            "approval_revocation_observed INTEGER NOT NULL DEFAULT 0",
            "approval_revocation_observed INTEGER NOT NULL DEFAULT 1",
        ),
    ] {
        rejects_after_ddl_replacement(table, old, new);
    }
}

#[test]
fn preflight_rejects_v14_without_activation_binding_constraints() {
    for (table, old, new) in [
        (
            "provider_runtime_authority_state",
            "CHECK(activation_binding_kind IN ('legacy_unbound', 'protected_v2', 'external_owner_private'))",
            "",
        ),
        (
            "provider_runtime_authority_state",
            "CHECK(length(activation_binding_digest) = 32)",
            "",
        ),
        (
            "provider_execution_admissions",
            "CHECK(activation_binding_kind IN ('legacy_unbound', 'protected_v2', 'external_owner_private'))",
            "",
        ),
        (
            "provider_execution_admissions",
            "CHECK(length(activation_binding_digest) = 32)",
            "",
        ),
    ] {
        rejects_after_ddl_replacement(table, old, new);
    }
}

#[test]
fn preflight_rejects_v14_with_a_malformed_inherited_v13_column_shape() {
    rejects_after_ddl_replacement(
        "provider_runtime_authority_state",
        "principal_id TEXT NOT NULL",
        "principal_id BLOB NOT NULL",
    );
}

#[test]
fn preflight_rejects_v14_with_tampered_unchanged_v13_provider_tables() {
    for (table, old, new) in [
        (
            "provider_budget_reservations",
            "amount INTEGER NOT NULL",
            "amount TEXT NOT NULL",
        ),
        (
            "provider_journal_key_refs",
            "key_version INTEGER NOT NULL",
            "key_version TEXT NOT NULL",
        ),
        (
            "provider_terminal_outbox",
            "terminal_sequence INTEGER NOT NULL",
            "terminal_sequence TEXT NOT NULL",
        ),
    ] {
        rejects_after_ddl_replacement(table, old, new);
    }
}

#[test]
fn preflight_accepts_the_released_v14_shape() {
    let (_directory, path) = released_v14_database("released-v14");
    preflight_existing_file(&path).unwrap();
    SqliteProviderExecutionStore::open(&path).unwrap();
}
