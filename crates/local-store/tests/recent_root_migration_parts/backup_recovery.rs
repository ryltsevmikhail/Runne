use std::path::Path;

use gocode_local_store::{
    LocalStore, StoreOpenError, pre_v5_migration_backup_path, verify_pre_v5_migration_backup,
};
use rusqlite::{Connection, params};

use super::v4_database;

fn snapshot(source: &Path, target: &Path) {
    let connection = Connection::open(source).expect("open v4 source");
    connection
        .execute(
            "VACUUM main INTO ?1",
            params![target.to_str().expect("utf8 path")],
        )
        .expect("snapshot v4 source");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600))
            .expect("private snapshot");
    }
}

fn version(path: &Path) -> i64 {
    Connection::open(path)
        .expect("open database")
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("schema version")
}

#[test]
fn valid_final_or_temp_backup_resumes_without_recreation() {
    for temporary in [false, true] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("profile.sqlite3");
        v4_database(&path, &[("/private/root", 41, 20)]);
        let final_path = pre_v5_migration_backup_path(&path).expect("backup path");
        let artifact = if temporary {
            final_path.with_extension("sqlite3.tmp")
        } else {
            final_path.clone()
        };
        snapshot(&path, &artifact);

        drop(LocalStore::open(&path).expect("resume migration"));
        assert_eq!(version(&path), 5);
        assert!(final_path.exists());
        assert!(!final_path.with_extension("sqlite3.tmp").exists());
        verify_pre_v5_migration_backup(&path).expect("independent backup verification");
    }
}

#[cfg(unix)]
#[test]
fn hard_link_promotion_crash_window_resumes_without_ambiguity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(&path, &[("/private/root", 41, 20)]);
    let final_path = pre_v5_migration_backup_path(&path).expect("backup path");
    let temporary = final_path.with_extension("sqlite3.tmp");
    snapshot(&path, &temporary);
    std::fs::hard_link(&temporary, &final_path).expect("interrupted promotion");

    drop(LocalStore::open(&path).expect("resume interrupted promotion"));
    assert_eq!(version(&path), 5);
    assert!(final_path.exists());
    assert!(!temporary.exists());
}

#[test]
fn backup_captures_committed_hot_wal_data() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(&path, &[("/private/root", 41, 20)]);
    let writer = Connection::open(&path).expect("open v4 writer");
    writer
        .execute_batch("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;")
        .expect("enable hot wal");
    writer
        .execute("UPDATE projects SET name = 'from-wal'", [])
        .expect("commit wal change");

    drop(LocalStore::open(&path).expect("migrate hot wal source"));
    let backup = verify_pre_v5_migration_backup(&path).expect("verify backup");
    let name: String = Connection::open(backup.path)
        .expect("open backup")
        .query_row("SELECT name FROM projects WHERE id = 41", [], |row| {
            row.get(0)
        })
        .expect("wal row in backup");
    assert_eq!(name, "from-wal");
}

#[test]
fn conflicting_or_incomplete_artifacts_leave_v4_untouched() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(&path, &[("/private/root", 41, 20)]);
    let final_path = pre_v5_migration_backup_path(&path).expect("backup path");
    let temporary = final_path.with_extension("sqlite3.tmp");
    snapshot(&path, &final_path);
    snapshot(&path, &temporary);
    assert!(matches!(
        LocalStore::open(&path),
        Err(StoreOpenError::PreV5BackupConflict)
    ));
    assert_eq!(version(&path), 4);
    assert!(final_path.exists() && temporary.exists());

    std::fs::remove_file(&final_path).expect("remove test artifact");
    std::fs::write(&temporary, b"incomplete").expect("incomplete artifact");
    assert!(matches!(
        LocalStore::open(&path),
        Err(StoreOpenError::PreV5BackupRecoveryRequired)
    ));
    assert_eq!(version(&path), 4);
    assert_eq!(
        std::fs::read(&temporary).expect("artifact remains"),
        b"incomplete"
    );
}

#[test]
fn mismatch_and_v5_sidecars_are_handled_without_mutation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(&path, &[("/private/root", 41, 20)]);
    let final_path = pre_v5_migration_backup_path(&path).expect("backup path");
    snapshot(&path, &final_path);
    Connection::open(&path)
        .expect("open changed source")
        .execute("UPDATE projects SET name = 'changed'", [])
        .expect("change v4 source");
    assert!(matches!(
        LocalStore::open(&path),
        Err(StoreOpenError::PreV5BackupSourceMismatch)
    ));
    assert_eq!(version(&path), 4);

    std::fs::remove_file(&final_path).expect("remove mismatch artifact");
    drop(LocalStore::open(&path).expect("migrate current v4 source"));
    std::fs::write(&final_path, b"v5 ignores artifacts").expect("malicious final");
    std::fs::write(
        final_path.with_extension("sqlite3.tmp"),
        b"v5 ignores temporary",
    )
    .expect("malicious temporary");
    assert!(
        LocalStore::open(&path).is_ok(),
        "v5 must not inspect sidecars"
    );
}

#[cfg(unix)]
#[test]
fn unsafe_backup_artifacts_are_rejected_without_replacement() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(&path, &[("/private/root", 41, 20)]);
    let final_path = pre_v5_migration_backup_path(&path).expect("backup path");
    symlink(&path, &final_path).expect("unsafe symlink");
    assert!(matches!(
        LocalStore::open(&path),
        Err(StoreOpenError::PreV5BackupConflict)
    ));
    assert_eq!(version(&path), 4);
    assert!(
        std::fs::symlink_metadata(&final_path)
            .expect("symlink remains")
            .file_type()
            .is_symlink()
    );

    std::fs::remove_file(&final_path).expect("remove symlink fixture");
    snapshot(&path, &final_path);
    let sidecar = format!("{}-wal", final_path.to_string_lossy());
    std::fs::write(&sidecar, b"unsafe sidecar").expect("sidecar");
    assert!(matches!(
        LocalStore::open(&path),
        Err(StoreOpenError::PreV5BackupInvalid)
    ));
    assert_eq!(version(&path), 4);
    assert!(final_path.exists());
    assert_eq!(
        std::fs::read(sidecar).expect("sidecar remains"),
        b"unsafe sidecar"
    );
}

#[cfg(unix)]
#[test]
fn live_database_hard_links_are_rejected_without_v5_mutation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(&path, &[("/private/root", 41, 20)]);
    let final_path = pre_v5_migration_backup_path(&path).expect("backup path");
    let temporary = final_path.with_extension("sqlite3.tmp");
    for artifact in [&final_path, &temporary] {
        std::fs::hard_link(&path, artifact).expect("live hard link");
        assert!(matches!(
            LocalStore::open(&path),
            Err(StoreOpenError::PreV5BackupConflict)
        ));
        assert_eq!(version(&path), 4);
        assert!(artifact.exists());
        std::fs::remove_file(artifact).expect("remove fixture link");
    }
}

#[test]
fn vacuum_into_accepts_a_precreated_empty_private_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let source = directory.path().join("source.sqlite3");
    let target = directory.path().join("target.sqlite3");
    Connection::open(&source)
        .expect("open source")
        .execute_batch(
            "CREATE TABLE source_data (value TEXT); INSERT INTO source_data VALUES ('ok');",
        )
        .expect("source data");
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&target)
        .expect("precreate target");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("private target");
    }
    Connection::open(&source)
        .expect("reopen source")
        .execute(
            "VACUUM main INTO ?1",
            params![target.to_str().expect("utf8 target")],
        )
        .expect("vacuum into precreated target");
    assert_eq!(
        Connection::open(target)
            .expect("open snapshot")
            .query_row("SELECT value FROM source_data", [], |row| row
                .get::<_, String>(0))
            .expect("snapshot row"),
        "ok"
    );
}

#[cfg(feature = "test-support")]
#[test]
fn backup_failpoints_resume_to_v5() {
    use gocode_local_store::recent_root_backup_test_support::{
        AFTER_FILE_DURABLE, AFTER_PRIVATE_CREATE, AFTER_PUBLISH, AFTER_PUBLISH_DURABLE,
        AFTER_SNAPSHOT, BEFORE_MIGRATION, INSIDE_MIGRATION, set_failpoint,
    };

    for stage in [
        AFTER_PRIVATE_CREATE,
        AFTER_SNAPSHOT,
        AFTER_FILE_DURABLE,
        AFTER_PUBLISH,
        AFTER_PUBLISH_DURABLE,
        BEFORE_MIGRATION,
        INSIDE_MIGRATION,
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("profile.sqlite3");
        v4_database(&path, &[("/private/root", 41, 20)]);
        set_failpoint(Some(stage));
        assert!(matches!(
            LocalStore::open(&path),
            Err(StoreOpenError::PreV5BackupRecoveryRequired)
        ));
        set_failpoint(None);
        drop(LocalStore::open(&path).expect("resume v5 migration"));
        assert_eq!(version(&path), 5, "{stage}");
    }
}
