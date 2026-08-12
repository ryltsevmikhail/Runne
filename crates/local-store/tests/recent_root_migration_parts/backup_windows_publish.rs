#![cfg(all(windows, feature = "test-support"))]

use gocode_local_store::{
    LocalStore, StoreOpenError, pre_v5_migration_backup_path, verify_pre_v5_migration_backup,
};
use rusqlite::Connection;

use super::v4_database;

#[test]
fn write_through_publish_failpoints_leave_one_final_backup_and_resume() {
    use gocode_local_store::recent_root_backup_test_support::{
        AFTER_PUBLISH, AFTER_PUBLISH_DURABLE, set_failpoint,
    };

    for stage in [AFTER_PUBLISH, AFTER_PUBLISH_DURABLE] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("profile.sqlite3");
        v4_database(&path, &[("/private/root", 41, 20)]);
        let final_path = pre_v5_migration_backup_path(&path).expect("backup path");
        let temporary = final_path.with_extension("sqlite3.tmp");
        set_failpoint(Some(stage));
        assert!(matches!(
            LocalStore::open(&path),
            Err(StoreOpenError::PreV5BackupRecoveryRequired)
        ));
        set_failpoint(None);
        assert!(final_path.exists() && !temporary.exists(), "{stage}");
        verify_pre_v5_migration_backup(&path).expect("verified final backup");
        drop(LocalStore::open(&path).expect("resume v5 migration"));
        assert_eq!(version(&path), 5, "{stage}");
    }
}

fn version(path: &std::path::Path) -> i64 {
    Connection::open(path)
        .expect("inspect database")
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("version")
}
