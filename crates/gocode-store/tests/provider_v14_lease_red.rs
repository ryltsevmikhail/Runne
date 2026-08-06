use gocode_store::provider::SqliteProviderExecutionStore;
use gocode_store::schema::CURRENT_SCHEMA_VERSION;
use rusqlite::Connection;

fn opened_database() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider-v14.sqlite");
    SqliteProviderExecutionStore::open(&path).unwrap();
    (directory, path)
}

#[test]
fn v13_upgrade_requires_v14_legacy_unbound_lease_columns() {
    let (_directory, path) = opened_database();
    let connection = Connection::open(path).unwrap();
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    assert_eq!(CURRENT_SCHEMA_VERSION, 15);

    let columns = connection
        .prepare("PRAGMA table_info('provider_runtime_authority_state')")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for required in [
        "capability_expires_at",
        "capability_revocation_epoch",
        "approval_revocation_epoch",
        "activation_binding_kind",
        "activation_binding_digest",
    ] {
        assert!(columns.contains(&required.to_owned()), "missing {required}");
    }
}

#[test]
fn v14_lease_schema_exposes_non_secret_utilization_snapshot_columns() {
    let (_directory, path) = opened_database();
    let connection = Connection::open(path).unwrap();
    let value: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('provider_runtime_authority_state')
             WHERE name IN ('token_budget_limit', 'token_budget_reserved',
                            'token_budget_settled', 'cost_budget_limit_micros',
                            'cost_budget_reserved_micros', 'cost_budget_settled_micros')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(value, 6);
}

#[test]
fn v14_database_reopens_after_migration() {
    let (_directory, path) = opened_database();
    SqliteProviderExecutionStore::open(&path).unwrap();
}
