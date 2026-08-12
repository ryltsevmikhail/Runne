use super::{Connection, LocalStore, v4_database};

#[test]
fn every_v4_check_or_default_mutation_fails_before_migration() {
    for (table, from, to) in [
        ("settings", "DEFAULT 1", "DEFAULT 2"),
        ("drafts", "revision >= 1", "revision >= 0"),
        ("projections", "event_sequence >= 1", "event_sequence >= 0"),
        ("event_journal", "generation >= 0", "generation >= 1"),
        ("replay_cursors", "generation >= 0", "generation >= 1"),
        ("window_layout", "revision >= 1", "revision >= 0"),
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("profile.sqlite3");
        v4_database(&path, &[("/private/root", 41, 20)]);
        rewrite_table(&path, table, from, to);
        assert!(LocalStore::open(&path).is_err(), "{table}");
        assert_eq!(version(&path), 4);
    }
}

#[test]
fn v4_meta_default_mutation_fails_before_migration() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(&path, &[("/private/root", 41, 20)]);
    let connection = Connection::open(&path).expect("database");
    let sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'meta'",
            [],
            |row| row.get(0),
        )
        .expect("meta sql");
    let rewritten = sql.replacen("DEFAULT 0", "DEFAULT 1", 1);
    assert_ne!(rewritten, sql, "meta fixture must be canonical");
    connection
        .execute_batch(&format!(
            "DROP TABLE meta; {rewritten}; \
             INSERT INTO meta (singleton, schema_version, db_generation) VALUES (1, 4, 9);"
        ))
        .expect("rewrite meta");
    drop(connection);

    assert!(LocalStore::open(&path).is_err());
    assert_eq!(version(&path), 4);
}

#[test]
fn schema_only_backup_mutation_is_rejected_with_identical_rows() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(&path, &[("/private/root", 41, 20)]);
    let backup = gocode_local_store::pre_v5_migration_backup_path(&path).expect("backup path");
    let source = Connection::open(&path).expect("source");
    source
        .execute("VACUUM main INTO ?1", [backup.to_str().expect("utf8")])
        .expect("snapshot");
    rewrite_table(&backup, "settings", "DEFAULT 1", "DEFAULT 2");

    assert!(LocalStore::open(&path).is_err());
    assert_eq!(version(&path), 4);
}

fn rewrite_table(path: &std::path::Path, table: &str, from: &str, to: &str) {
    let connection = Connection::open(path).expect("database");
    let sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .expect("table sql");
    let rewritten = sql.replacen(from, to, 1);
    assert_ne!(rewritten, sql, "{table} fixture must be canonical");
    connection
        .execute_batch(&format!("DROP TABLE {table}; {rewritten};"))
        .expect("rewrite table");
}

fn version(path: &std::path::Path) -> i64 {
    Connection::open(path)
        .expect("database")
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("version")
}
