#[cfg(target_os = "linux")]
#[test]
fn linux_managed_identity_anchor_drop_preserves_live_wal_locks() {
    let (_root, path) = identity_fixture("linux-wal-anchor-locks");
    let writer = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    writer
        .execute_batch(
            "CREATE TABLE wal_anchor_probe (value INTEGER NOT NULL);
             INSERT INTO wal_anchor_probe VALUES (1);",
        )
        .unwrap();

    writer
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO wal_anchor_probe VALUES (2);")
        .unwrap();
    let extra_identity = ConnectionIdentityGuard::owner_private(&path).unwrap();
    drop(extra_identity);

    let lock_probe = run_wal_probe("lock", &path);
    assert!(lock_probe.contains("lock-probe: blocked"), "{lock_probe}");
    writer.execute_batch("COMMIT;").unwrap();
    assert!(run_wal_probe("read", &path).contains("read-count:2"));

    drop(writer);
    assert!(run_wal_probe("read", &path).contains("read-count:2"));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_o_path_identity_anchor_rejects_symlink_handles() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("database");
    let link = directory.path().join("link");
    std::fs::write(&target, b"database").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    assert!(matches!(
        RetainedFileIdentity::open(&link),
        Err(SchemaOpenDiagnostic::FileIdentityUncertain)
    ));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "subprocess helper for linux_managed_identity_anchor_drop_preserves_live_wal_locks"]
fn linux_wal_identity_anchor_probe_child() {
    let Some(path) = std::env::var_os("RUNNE_SCHEMA_WAL_LOCK_PROBE_PATH") else {
        return;
    };
    let mode = std::env::var("RUNNE_SCHEMA_WAL_LOCK_PROBE_MODE").unwrap();
    let connection = Connection::open(path).unwrap();
    if mode == "lock" {
        connection
            .busy_timeout(std::time::Duration::from_millis(150))
            .unwrap();
        match connection.execute_batch("BEGIN IMMEDIATE;") {
            Ok(()) => {
                println!("lock-probe: acquired");
                connection.execute_batch("ROLLBACK;").unwrap();
            }
            Err(rusqlite::Error::SqliteFailure(error, _))
                if matches!(
                    error.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) => println!("lock-probe: blocked"),
            Err(_) => panic!("lock probe returned an unexpected SQLite error"),
        }
    } else {
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM wal_anchor_probe", [], |row| row.get(0))
            .unwrap();
        println!("read-count:{count}");
    }
}

#[cfg(target_os = "linux")]
fn run_wal_probe(mode: &str, path: &Path) -> String {
    use std::process::Command;
    use std::time::{Duration, Instant};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "schema::tests::linux_wal_identity_anchor_probe_child",
            "--ignored",
            "--nocapture",
        ])
        .env("RUNNE_SCHEMA_WAL_LOCK_PROBE_PATH", path)
        .env("RUNNE_SCHEMA_WAL_LOCK_PROBE_MODE", mode)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("WAL child probe timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "WAL child probe failed with status {}",
        output.status
    );
    String::from_utf8(output.stdout).unwrap()
}
