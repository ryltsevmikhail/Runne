#![cfg(feature = "test-support")]

use runne_local_store::{
    LocalStore, StoreOpenError, pre_v4_migration_backup_path, verify_pre_v4_migration_backup,
};
use rusqlite::Connection;

#[test]
fn pre_v4_backup_failpoints_resume_fresh_and_historical_sources() {
    use runne_local_store::recent_root_backup_test_support::{
        AFTER_FILE_DURABLE, AFTER_PRIVATE_CREATE, AFTER_PUBLISH, AFTER_PUBLISH_DURABLE,
        AFTER_SNAPSHOT, set_failpoint,
    };

    for source_version in [0, 1, 2, 3] {
        for stage in [
            AFTER_PRIVATE_CREATE,
            AFTER_SNAPSHOT,
            AFTER_FILE_DURABLE,
            AFTER_PUBLISH,
            AFTER_PUBLISH_DURABLE,
        ] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let path = directory.path().join(format!("v{source_version}.sqlite3"));
            prepare(&path, source_version);
            set_failpoint(Some(stage));
            assert!(matches!(
                LocalStore::open(&path),
                Err(StoreOpenError::MigrationBackupUnavailable)
            ));
            set_failpoint(None);
            let backup = pre_v4_migration_backup_path(&path).expect("backup path");
            let temporary = backup.with_extension("sqlite3.tmp");
            let artifact = if backup.exists() { &backup } else { &temporary };
            assert_private(artifact);
            drop(LocalStore::open(&path).expect("resume v5 migration"));
            assert_eq!(version(&path), 5, "v{source_version} {stage}");
            verify_pre_v4_migration_backup(&path).expect("verified pre-v4 backup");
        }
    }
}

fn prepare(path: &std::path::Path, version: i64) {
    match version {
        0 => {}
        1 | 2 => historical_database(path, version),
        3 => v3_database(path),
        _ => unreachable!(),
    }
}

fn historical_database(path: &std::path::Path, version: i64) {
    let connection = Connection::open(path).expect("historical database");
    connection
        .execute_batch(
            "CREATE TABLE settings (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1) STRICT;",
        )
        .expect("v1 schema");
    if version == 2 {
        connection
            .execute_batch(
                "CREATE TABLE projects (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE, last_opened_at INTEGER NOT NULL) STRICT;",
            )
            .expect("v2 schema");
    }
    connection
        .pragma_update(None, "user_version", version)
        .expect("version");
}

fn v3_database(path: &std::path::Path) {
    use runne_local_store::recent_root_backup_test_support::{AFTER_PRIVATE_CREATE, set_failpoint};

    set_failpoint(Some(AFTER_PRIVATE_CREATE));
    assert!(matches!(
        LocalStore::open(path),
        Err(StoreOpenError::MigrationBackupUnavailable)
    ));
    set_failpoint(None);
    let temporary = pre_v4_migration_backup_path(path)
        .expect("backup path")
        .with_extension("sqlite3.tmp");
    std::fs::remove_file(temporary).expect("known fixture temporary");
    assert_eq!(version(path), 3);
}

fn assert_private(path: &std::path::Path) {
    assert!(path.exists(), "backup artifact exists");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

fn version(path: &std::path::Path) -> i64 {
    Connection::open(path)
        .expect("inspect database")
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("version")
}
