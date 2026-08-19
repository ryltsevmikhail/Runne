use super::{Connection, LocalStore, PROJECT_ID, WORKSPACE_ID, v4_database};

#[test]
fn recent_root_timestamps_are_limited_to_javascript_safe_integers() {
    let directory = tempfile::tempdir().expect("temp directory");
    let mut store =
        LocalStore::open(&directory.path().join("profile.sqlite3")).expect("open store");
    store
        .record_recent_root(
            PROJECT_ID,
            WORKSPACE_ID,
            "Max",
            9_007_199_254_740_991,
            "native",
        )
        .expect("max timestamp");
    assert!(
        store
            .record_recent_root(
                PROJECT_ID,
                "01890e00-0000-7000-8000-000000000003",
                "Too late",
                9_007_199_254_740_992,
                "other"
            )
            .is_err()
    );
}

#[test]
fn v5_schema_version_meta_and_extra_objects_fail_closed() {
    for sql in [
        "PRAGMA user_version = 4",
        "UPDATE meta SET schema_version = 4 WHERE singleton = 1",
        "DROP TABLE meta; CREATE TABLE meta (singleton INTEGER, schema_version INTEGER); INSERT INTO meta VALUES (1, 5), (2, 5)",
        "CREATE TABLE injected (value TEXT)",
        "ALTER TABLE drafts ADD COLUMN injected TEXT",
        "DROP TABLE window_layout",
        "CREATE TRIGGER recent_roots_trigger AFTER INSERT ON recent_roots BEGIN SELECT 1; END",
    ] {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        drop(LocalStore::open(&path).expect("create v5"));
        let connection = Connection::open(&path).expect("open v5");
        connection.execute_batch(sql).expect("corrupt v5");
        drop(connection);
        assert!(LocalStore::open(&path).is_err(), "{sql}");
    }
}

#[test]
fn v5_semantic_schema_mutations_fail_closed() {
    for (name, sql) in [
        (
            "settings-default",
            "DROP TABLE settings; CREATE TABLE settings (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 2) STRICT;",
        ),
        (
            "meta-default-check",
            "DROP TABLE meta; CREATE TABLE meta (singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1), schema_version INTEGER NOT NULL CHECK (schema_version >= 1), db_generation INTEGER NOT NULL CHECK (db_generation >= 1), last_transaction_digest TEXT, commit_marker INTEGER NOT NULL DEFAULT 1 CHECK (commit_marker IN (0, 1))) STRICT; INSERT INTO meta VALUES (1, 5, 1, NULL, 1);",
        ),
        (
            "projection-check",
            "DROP TABLE projections; CREATE TABLE projections (runtime_authority TEXT NOT NULL, principal TEXT NOT NULL, lineage TEXT NOT NULL, scope TEXT NOT NULL, binding_digest TEXT NOT NULL, projection_revision INTEGER NOT NULL, projection_digest TEXT NOT NULL, event_sequence INTEGER NOT NULL CHECK (event_sequence >= 0), payload BLOB NOT NULL, PRIMARY KEY (runtime_authority, principal, lineage, scope)) STRICT;",
        ),
        (
            "unique-columns",
            "DROP TABLE mutation_ledger; CREATE TABLE mutation_ledger (runtime_authority TEXT NOT NULL, principal TEXT NOT NULL, operation_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, target TEXT NOT NULL, disposition TEXT NOT NULL, PRIMARY KEY (runtime_authority, principal, operation_id), UNIQUE (runtime_authority, principal, target)) STRICT;",
        ),
        (
            "collation",
            "DROP TABLE settings; CREATE TABLE settings (key TEXT COLLATE NOCASE PRIMARY KEY NOT NULL, value TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1) STRICT;",
        ),
        (
            "recent-root-or",
            "DROP TABLE recent_roots; CREATE TABLE recent_roots (project_id TEXT, workspace_id TEXT, display_name TEXT NOT NULL, last_opened_at INTEGER NOT NULL CHECK (last_opened_at >= 0 AND last_opened_at <= 9007199254740991), root_state TEXT NOT NULL CHECK (root_state IN ('ready', 'migration_required')), native_root_metadata TEXT, legacy_project_id INTEGER UNIQUE, CHECK (1), UNIQUE (workspace_id), UNIQUE (native_root_metadata)) STRICT;",
        ),
        (
            "recent-root-ready-case",
            "DROP TABLE recent_roots; CREATE TABLE recent_roots (project_id TEXT, workspace_id TEXT, display_name TEXT NOT NULL, last_opened_at INTEGER NOT NULL CHECK (last_opened_at >= 0 AND last_opened_at <= 9007199254740991), root_state TEXT NOT NULL CHECK (root_state IN ('READY', 'migration_required')), native_root_metadata TEXT, legacy_project_id INTEGER UNIQUE, CHECK ((root_state = 'ready' AND project_id IS NOT NULL AND workspace_id IS NOT NULL AND native_root_metadata IS NOT NULL AND legacy_project_id IS NULL) OR (root_state = 'migration_required' AND project_id IS NULL AND workspace_id IS NULL AND legacy_project_id IS NOT NULL AND native_root_metadata IS NOT NULL)), UNIQUE (workspace_id), UNIQUE (native_root_metadata)) STRICT;",
        ),
        (
            "glob-literal-whitespace",
            "DROP TABLE projections; CREATE TABLE projections (runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0), principal TEXT NOT NULL CHECK (length(principal) > 0), lineage TEXT NOT NULL CHECK (length(lineage) > 0), scope TEXT NOT NULL CHECK (length(scope) > 0), binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 64 AND binding_digest NOT GLOB '* [^0-9a-f]*'), projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0), projection_digest TEXT NOT NULL CHECK (length(projection_digest) = 64 AND projection_digest NOT GLOB '*[^0-9a-f]*'), event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1), payload BLOB NOT NULL CHECK (json_valid(payload) = 1), PRIMARY KEY (runtime_authority, principal, lineage, scope)) STRICT;",
        ),
    ] {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        drop(LocalStore::open(&path).expect("create v5"));
        let connection = Connection::open(&path).expect("open v5");
        connection.execute_batch(sql).expect("mutate v5 schema");
        drop(connection);
        assert!(LocalStore::open(&path).is_err(), "{name}");
    }
}

#[test]
fn v4_extra_column_trigger_or_dependency_is_rejected_before_drop() {
    for sql in [
        "ALTER TABLE projects ADD COLUMN injected TEXT",
        "CREATE TRIGGER projects_trigger AFTER INSERT ON projects BEGIN SELECT 1; END",
        "CREATE VIEW projects_dependency AS SELECT * FROM projects",
    ] {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        v4_database(&path, &[("/private/root", 41, 20)]);
        let connection = Connection::open(&path).expect("open v4");
        connection.execute_batch(sql).expect("corrupt v4");
        drop(connection);
        assert!(LocalStore::open(&path).is_err(), "{sql}");
        let connection = Connection::open(path).expect("inspect v4");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("version");
        assert_eq!(version, 4);
    }
}
