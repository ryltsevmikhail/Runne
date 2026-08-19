use runne_local_store::{LocalStore, StoreOpenError, pre_v5_migration_backup_path};
use rusqlite::{Connection, params};

use super::v4_database;

const CHILD_PATH: &str = "RUNNE_P4_STREAMING_PATH";

#[test]
fn large_near_end_backup_mismatch_is_streaming() {
    if let Ok(path) = std::env::var(CHILD_PATH) {
        assert!(matches!(
            LocalStore::open(std::path::Path::new(&path)),
            Err(StoreOpenError::PreV5BackupSourceMismatch)
        ));
        return;
    }
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("profile.sqlite3");
    v4_database(&path, &[("/private/root", 1, 1)]);
    let payload = "x".repeat(16 * 1024);
    let connection = Connection::open(&path).expect("open v4 database");
    for id in 2..=6_000 {
        connection
            .execute(
                "INSERT INTO projects (id, name, path, last_opened_at) VALUES (?1, ?2, ?3, ?1)",
                params![id, payload, format!("/private/root-{id}")],
            )
            .expect("large project row");
    }
    let backup = pre_v5_migration_backup_path(&path).expect("backup path");
    connection
        .execute(
            "VACUUM main INTO ?1",
            [backup.to_str().expect("utf8 backup")],
        )
        .expect("snapshot");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o600))
            .expect("private backup");
    }
    connection
        .execute("UPDATE projects SET name = 'mismatch' WHERE id = 6000", [])
        .expect("near-end mismatch");
    drop(connection);
    let mut child = memory_capped_child(std::env::current_exe().expect("test executable"));
    let status = child
        .env(CHILD_PATH, &path)
        .status()
        .expect("memory-capped child");
    assert!(status.success(), "child comparator must remain bounded");
}

#[cfg(unix)]
fn memory_capped_child(executable: std::path::PathBuf) -> std::process::Command {
    let mut child = std::process::Command::new("sh");
    child.args(["-c", "ulimit -v 196608; exec \"$1\" --exact \"$2\"", "sh"]);
    child
        .arg(executable)
        .arg("backup_streaming::large_near_end_backup_mismatch_is_streaming");
    child
}

#[cfg(not(unix))]
fn memory_capped_child(executable: std::path::PathBuf) -> std::process::Command {
    let mut child = std::process::Command::new(executable);
    child.args([
        "--exact",
        "backup_streaming::large_near_end_backup_mismatch_is_streaming",
    ]);
    child
}
