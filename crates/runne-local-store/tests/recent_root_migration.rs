use runne_local_store::{LocalStore, RecentRoot, verify_pre_v5_migration_backup};
use rusqlite::{Connection, params};

const PROJECT_ID: &str = "01890e00-0000-7000-8000-000000000001";
const WORKSPACE_ID: &str = "01890e00-0000-7000-8000-000000000002";
type MigrationRow = (
    Option<String>,
    Option<String>,
    String,
    i64,
    String,
    i64,
    String,
);

#[path = "recent_root_migration_parts/backup_failpoint_contract.rs"]
mod backup_failpoint_contract;
#[path = "recent_root_migration_parts/backup_recovery.rs"]
mod backup_recovery;
#[path = "recent_root_migration_parts/backup_streaming.rs"]
mod backup_streaming;
#[path = "recent_root_migration_parts/backup_windows_publish.rs"]
mod backup_windows_publish;
#[path = "recent_root_migration_parts/pre_v4_backup_recovery.rs"]
mod pre_v4_backup_recovery;
#[path = "recent_root_migration_parts/schema.rs"]
mod schema;
#[path = "recent_root_migration_parts/v4_manifest.rs"]
mod v4_manifest;
#[path = "recent_root_migration_parts/versions.rs"]
mod versions;

fn v4_database(path: &std::path::Path, rows: &[(&str, i64, i64)]) {
    let connection = Connection::open(path).expect("create v4 database");
    connection
        .execute_batch(
            "
            CREATE TABLE settings (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1) STRICT;
            CREATE TABLE projects (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE, last_opened_at INTEGER NOT NULL) STRICT;
            CREATE TABLE meta (singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1), schema_version INTEGER NOT NULL CHECK (schema_version >= 1), db_generation INTEGER NOT NULL CHECK (db_generation >= 1), last_transaction_digest TEXT, commit_marker INTEGER NOT NULL DEFAULT 0 CHECK (commit_marker IN (0, 1))) STRICT;
            INSERT INTO meta (singleton, schema_version, db_generation) VALUES (1, 4, 9);
            CREATE TABLE drafts (runtime_authority TEXT NOT NULL, principal TEXT NOT NULL, project_id TEXT NOT NULL, run_id TEXT NOT NULL, body TEXT NOT NULL, revision INTEGER NOT NULL CHECK (revision >= 1), updated_at INTEGER NOT NULL CHECK (updated_at >= 0), PRIMARY KEY (runtime_authority, principal, project_id, run_id)) STRICT;
            CREATE TABLE projections (runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0), principal TEXT NOT NULL CHECK (length(principal) > 0), lineage TEXT NOT NULL CHECK (length(lineage) > 0), scope TEXT NOT NULL CHECK (length(scope) > 0), binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 64 AND binding_digest NOT GLOB '*[^0-9a-f]*'), projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0), projection_digest TEXT NOT NULL CHECK (length(projection_digest) = 64 AND projection_digest NOT GLOB '*[^0-9a-f]*'), event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1), payload BLOB NOT NULL CHECK (json_valid(payload) = 1), PRIMARY KEY (runtime_authority, principal, lineage, scope)) STRICT;
            CREATE TABLE event_journal (runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0), principal TEXT NOT NULL CHECK (length(principal) > 0), lineage TEXT NOT NULL CHECK (length(lineage) > 0), scope TEXT NOT NULL CHECK (length(scope) > 0), binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 64 AND binding_digest NOT GLOB '*[^0-9a-f]*'), event_id TEXT NOT NULL CHECK (length(event_id) > 0), cursor TEXT NOT NULL CHECK (length(cursor) > 0), generation INTEGER NOT NULL CHECK (generation >= 0), event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1), validated_event BLOB NOT NULL, event_digest TEXT NOT NULL CHECK (length(event_digest) = 64 AND event_digest NOT GLOB '*[^0-9a-f]*'), projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0), projection_digest TEXT NOT NULL CHECK (length(projection_digest) = 64 AND projection_digest NOT GLOB '*[^0-9a-f]*'), projected_payload BLOB NOT NULL CHECK (json_valid(projected_payload) = 1), PRIMARY KEY (runtime_authority, principal, lineage, scope, event_id), UNIQUE (runtime_authority, principal, lineage, scope, event_sequence), UNIQUE (runtime_authority, principal, lineage, scope, cursor)) STRICT;
            CREATE TABLE replay_cursors (runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0), principal TEXT NOT NULL CHECK (length(principal) > 0), lineage TEXT NOT NULL CHECK (length(lineage) > 0), scope TEXT NOT NULL CHECK (length(scope) > 0), binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 64 AND binding_digest NOT GLOB '*[^0-9a-f]*'), generation INTEGER NOT NULL CHECK (generation >= 0), applied_cursor TEXT NOT NULL CHECK (length(applied_cursor) > 0), event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1), projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0), projection_digest TEXT NOT NULL CHECK (length(projection_digest) = 64 AND projection_digest NOT GLOB '*[^0-9a-f]*'), PRIMARY KEY (runtime_authority, principal, lineage, scope)) STRICT;
            CREATE TABLE mutation_ledger (runtime_authority TEXT NOT NULL, principal TEXT NOT NULL, operation_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, target TEXT NOT NULL, disposition TEXT NOT NULL, PRIMARY KEY (runtime_authority, principal, operation_id), UNIQUE (runtime_authority, principal, idempotency_key)) STRICT;
            CREATE TABLE window_layout (profile TEXT NOT NULL, display_topology TEXT NOT NULL, geometry TEXT NOT NULL, revision INTEGER NOT NULL CHECK (revision >= 1), PRIMARY KEY (profile, display_topology)) STRICT;
            PRAGMA user_version = 4;
            ",
        )
        .expect("create schema");
    for (path_value, id, opened) in rows {
        connection
            .execute(
                "INSERT INTO projects (id, name, path, last_opened_at) VALUES (?1, 'workspace', ?2, ?3)",
                params![id, path_value, opened],
            )
            .expect("insert legacy row");
    }
}

#[test]
fn v4_numeric_projects_become_private_migration_required_roots() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(
        &path,
        &[("/private/alpha", 41, 20), ("/private/beta", 42, 30)],
    );
    let store = LocalStore::open(&path).expect("migrate v4 database");

    assert_eq!(store.diagnostics().expect("diagnostics").schema_version, 5);
    assert!(store.list_recent_roots().expect("list roots").is_empty());
    drop(store);

    let backup = verify_pre_v5_migration_backup(&path).expect("verify v4 rollback backup");
    assert_eq!(backup.schema_version, 4);

    let connection = Connection::open(path).expect("inspect migration");
    let rows: Vec<MigrationRow> = connection
        .prepare("SELECT project_id, workspace_id, display_name, last_opened_at, root_state, legacy_project_id, native_root_metadata FROM recent_roots ORDER BY last_opened_at")
        .expect("prepare")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows");
    assert_eq!(
        rows,
        vec![
            (
                None,
                None,
                "workspace".into(),
                20,
                "migration_required".into(),
                41,
                "/private/alpha".into()
            ),
            (
                None,
                None,
                "workspace".into(),
                30,
                "migration_required".into(),
                42,
                "/private/beta".into()
            ),
        ]
    );
}

#[test]
fn v5_empty_store_reopens_idempotently_and_orders_canonical_roots() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open empty store");
    assert_eq!(store.diagnostics().expect("diagnostics").schema_version, 5);
    assert!(store.list_recent_roots().expect("list roots").is_empty());

    store
        .record_recent_root(PROJECT_ID, WORKSPACE_ID, "Alpha", 7, "native-1")
        .expect("record alpha");
    store
        .record_recent_root(
            "01890e00-0000-7000-8000-000000000003",
            "01890e00-0000-7000-8000-000000000004",
            "Beta",
            8,
            "native-2",
        )
        .expect("record beta");
    drop(store);

    let store = LocalStore::open(&path).expect("reopen v5 store");
    let roots = store.list_recent_roots().expect("list roots");
    assert_eq!(
        roots
            .iter()
            .map(RecentRoot::display_name)
            .collect::<Vec<_>>(),
        ["Beta", "Alpha"]
    );
    assert_eq!(roots[1].project_id(), PROJECT_ID);
    assert_eq!(roots[1].workspace_id(), WORKSPACE_ID);
}

#[test]
fn project_inventory_preserves_workspaces_and_rejects_reparenting() {
    let directory = tempfile::tempdir().expect("temp directory");
    let mut store =
        LocalStore::open(&directory.path().join("profile.sqlite3")).expect("open store");
    store
        .record_recent_root(PROJECT_ID, WORKSPACE_ID, "One", 7, "native-one")
        .expect("one");
    store
        .record_recent_root(
            PROJECT_ID,
            "01890e00-0000-7000-8000-000000000003",
            "Two",
            8,
            "native-two",
        )
        .expect("two");
    let roots = store
        .list_project_roots(PROJECT_ID)
        .expect("project inventory");
    assert_eq!(roots.len(), 2);
    assert_eq!(
        store
            .get_workspace_root(WORKSPACE_ID)
            .expect("workspace")
            .expect("root")
            .display_name(),
        "One"
    );
    assert!(
        store
            .record_recent_root(
                "01890e00-0000-7000-8000-000000000004",
                WORKSPACE_ID,
                "Moved",
                9,
                "native-one"
            )
            .is_err()
    );
    assert_eq!(
        store
            .get_workspace_root(WORKSPACE_ID)
            .expect("workspace")
            .expect("root")
            .project_id(),
        PROJECT_ID
    );
}

#[test]
fn malformed_legacy_rows_fail_closed_without_advancing_schema() {
    for bad_name in ["", "a".repeat(257).as_str(), "bad\nname"] {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.sqlite3");
        v4_database(&path, &[("/private/root", 41, 20)]);
        let connection = Connection::open(&path).expect("open fixture");
        connection
            .execute("UPDATE projects SET name = ?1", [bad_name])
            .expect("corrupt name");
        drop(connection);
        assert!(LocalStore::open(&path).is_err(), "{bad_name:?} must reject");
        let connection = Connection::open(path).expect("inspect rejected database");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("version");
        assert_eq!(version, 4);
    }
}

#[test]
fn legacy_relative_or_duplicate_paths_fail_closed_without_numeric_id_casts() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(&path, &[("relative/root", 41, 20)]);
    assert!(LocalStore::open(&path).is_err());

    let path = directory.path().join("duplicate.sqlite3");
    v4_database(&path, &[("/private/one", 41, 20), ("/private/two", 42, 30)]);
    let connection = Connection::open(&path).expect("open fixture");
    connection
        .execute("DROP TABLE projects", [])
        .expect("replace projects");
    connection
        .execute_batch(
            "CREATE TABLE projects (id INTEGER, name TEXT, path TEXT, last_opened_at INTEGER);",
        )
        .expect("loose legacy table");
    for id in [41, 42] {
        connection
            .execute(
                "INSERT INTO projects VALUES (?1, 'workspace', '/private/duplicate', 20)",
                [id],
            )
            .expect("duplicate row");
    }
    drop(connection);
    assert!(LocalStore::open(&path).is_err());
    let connection = Connection::open(path).expect("inspect rejected database");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("version");
    assert_eq!(version, 4);
}

#[test]
fn null_or_oversized_legacy_paths_fail_closed_without_partial_migration() {
    for (name, path_value) in [
        ("null", None),
        ("oversized", Some(format!("/{}", "a".repeat(4096)))),
    ] {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join(format!("{name}.sqlite3"));
        v4_database(&path, &[("/private/fixture", 41, 20)]);
        let connection = Connection::open(&path).expect("open fixture");
        connection
            .execute("DROP TABLE projects", [])
            .expect("replace projects");
        connection
            .execute_batch(
                "CREATE TABLE projects (id INTEGER, name TEXT, path TEXT, last_opened_at INTEGER);",
            )
            .expect("loose legacy table");
        connection
            .execute(
                "INSERT INTO projects VALUES (41, 'workspace', ?1, 20)",
                [path_value],
            )
            .expect("insert corrupt row");
        drop(connection);

        assert!(LocalStore::open(&path).is_err(), "{name} row must reject");
        let connection = Connection::open(path).expect("inspect rejected database");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("version");
        assert_eq!(version, 4);
        let migrated: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'recent_roots')",
                [],
                |row| row.get(0),
            )
            .expect("migration table");
        assert!(!migrated);
    }
}
