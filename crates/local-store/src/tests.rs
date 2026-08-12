use super::{
    DatabaseRecoveryState, LocalStore, PreparedMutation, anchor_db_generation,
    classify_database_recovery, verify_anchor,
};
use gocode_secure_store::{AnchorStatus, SecureStore, SecureStoreError};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

#[derive(Default)]
struct MemorySecureStore {
    anchor: Mutex<Option<u64>>,
}

impl SecureStore for MemorySecureStore {
    fn store_anchor(&self, generation: u64) -> Result<(), SecureStoreError> {
        *self.anchor.lock().expect("anchor lock") = Some(generation);
        Ok(())
    }

    fn read_anchor(&self) -> Result<Option<u64>, SecureStoreError> {
        Ok(*self.anchor.lock().expect("anchor lock"))
    }

    fn delete_anchor(&self) -> Result<(), SecureStoreError> {
        *self.anchor.lock().expect("anchor lock") = None;
        Ok(())
    }
}

#[test]
fn anchors_current_database_generation_and_verifies_normal_state() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let store = LocalStore::open(&path).expect("open store");
    let secure_store = MemorySecureStore::default();

    anchor_db_generation(&store, &secure_store).expect("anchor generation");

    assert_eq!(secure_store.read_anchor().expect("read anchor"), Some(1));
    assert_eq!(
        verify_anchor(&store, &secure_store).expect("verify anchor"),
        AnchorStatus::Normal
    );
}

#[test]
fn database_one_ahead_requires_a_valid_commit_marker() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let store = LocalStore::open(&path).expect("open store");
    let secure_store = MemorySecureStore {
        anchor: Mutex::new(Some(1)),
    };
    store
        .connection
        .execute(
            "UPDATE meta SET db_generation = 2, commit_marker = 0 WHERE singleton = 1",
            [],
        )
        .expect("set unverified generation");

    assert_eq!(
        verify_anchor(&store, &secure_store).expect("verify anchor"),
        AnchorStatus::DbTooFarAhead {
            db_gen: 2,
            anchor: 1,
        }
    );

    store
        .connection
        .execute("UPDATE meta SET commit_marker = 1 WHERE singleton = 1", [])
        .expect("set valid commit marker");

    assert_eq!(
        verify_anchor(&store, &secure_store).expect("verify anchor"),
        AnchorStatus::DbOneAhead {
            db_gen: 2,
            anchor: 1,
        }
    );
}

#[test]
fn persists_settings_across_reopen() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");

    {
        let mut store = LocalStore::open(&path).expect("open store");
        store
            .set_setting("appearance.theme", "light")
            .expect("save setting");
    }

    let store = LocalStore::open(&path).expect("reopen store");
    assert_eq!(
        Some("light".to_owned()),
        store.get_setting("appearance.theme").expect("read setting")
    );
}

#[test]
fn persists_local_projects_and_reopens_the_most_recent_workspace() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let project_path = directory.path().join("alpha");
    std::fs::create_dir(&project_path).expect("create project directory");
    let canonical_project_path = project_path.canonicalize().expect("canonical project path");

    let project_id = {
        let mut store = LocalStore::open(&path).expect("open store");
        store
            .open_local_project(&project_path)
            .expect("persist local project")
            .id
    };

    let store = LocalStore::open(&path).expect("reopen store");
    let projects = store.list_projects().expect("list projects");

    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].id, project_id);
    assert_eq!(projects[0].name, "alpha");
    assert_eq!(projects[0].path, canonical_project_path);
    assert_eq!(
        store
            .get_project(project_id)
            .expect("load project")
            .expect("stored project")
            .path,
        canonical_project_path
    );
}

#[test]
fn rejects_a_local_project_path_that_is_not_a_directory() {
    let directory = tempfile::tempdir().expect("temp directory");
    let mut store =
        LocalStore::open(&directory.path().join("profile.sqlite3")).expect("open store");

    let error = store
        .open_local_project(Path::new("missing-project"))
        .expect_err("missing path must be rejected");

    assert_eq!(error.to_string(), "local project path is not a directory");
    assert!(store.list_projects().expect("list projects").is_empty());
}

#[test]
fn rejects_a_future_schema_version_without_rewriting_it() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let connection = Connection::open(&path).expect("create database");
    connection
        .pragma_update(None, "user_version", 99)
        .expect("set future schema");
    drop(connection);

    let Err(error) = LocalStore::open(&path) else {
        panic!("future schema must be rejected");
    };

    assert_eq!(error.to_string(), "unsupported database schema version: 99");
    let connection = Connection::open(path).expect("reopen database");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read schema version");
    assert_eq!(version, 99);
}

#[test]
fn migration_v5_creates_the_normative_recovery_schema() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");

    LocalStore::open(&path).expect("open and migrate store");

    let connection = Connection::open(path).expect("inspect database");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read schema version");
    assert_eq!(version, 5);

    for table in [
        "meta",
        "drafts",
        "projections",
        "event_journal",
        "replay_cursors",
        "mutation_ledger",
        "window_layout",
        "recent_roots",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .expect("inspect table");
        assert!(exists, "missing table {table}");
    }

    let generation: i64 = connection
        .query_row(
            "SELECT db_generation FROM meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read database generation");
    assert_eq!(generation, 1);
}

#[test]
fn classifies_every_documented_database_anchor_state() {
    use DatabaseRecoveryState::{
        AdvanceAnchor, Ambiguous, AnchorMissing, DatabaseMissing, FirstRun, Normal,
        RollbackDetected,
    };

    assert_eq!(classify_database_recovery(None, None, false), FirstRun);
    assert_eq!(classify_database_recovery(Some(4), Some(4), false), Normal);
    assert_eq!(
        classify_database_recovery(Some(3), Some(4), false),
        RollbackDetected
    );
    assert_eq!(
        classify_database_recovery(Some(5), Some(4), true),
        AdvanceAnchor
    );
    assert_eq!(
        classify_database_recovery(Some(5), Some(4), false),
        Ambiguous
    );
    assert_eq!(
        classify_database_recovery(Some(7), Some(4), true),
        Ambiguous
    );
    assert_eq!(
        classify_database_recovery(Some(4), None, false),
        AnchorMissing
    );
    assert_eq!(
        classify_database_recovery(None, Some(4), false),
        DatabaseMissing
    );
}

#[test]
fn prepared_mutation_is_durable_idempotent_and_identity_bound() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let mutation = PreparedMutation {
        runtime_authority: "runtime-1",
        principal: "user-1",
        operation_id: "operation-1",
        idempotency_key: "idempotency-1",
        target: "workspace-1",
    };

    assert_eq!(store.prepare_mutation(&mutation).expect("prepare"), 2);
    assert_eq!(
        store
            .prepare_mutation(&mutation)
            .expect("prepare duplicate"),
        2
    );

    let conflicting = PreparedMutation {
        target: "workspace-2",
        ..mutation
    };
    let error = store
        .prepare_mutation(&conflicting)
        .expect_err("identity conflict");
    assert_eq!(error.to_string(), "mutation identity conflict");

    let connection = Connection::open(path).expect("inspect database");
    let (count, generation): (i64, i64) = connection
        .query_row(
            "
                SELECT COUNT(*), meta.db_generation
                FROM mutation_ledger CROSS JOIN meta
                WHERE meta.singleton = 1
                ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read ledger");
    assert_eq!(count, 1);
    assert_eq!(generation, 2);
}
