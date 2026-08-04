#[test]
fn immutable_preflight_does_not_create_wal_sidecars() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("event log.db");
    let connection = Connection::open(&path).unwrap();
    apply_migrations(&connection).unwrap();
    drop(connection);
    assert!(!sidecar_path(&path, "-wal").exists());
    assert!(!sidecar_path(&path, "-shm").exists());

    preflight_existing_file(&path).unwrap();
    preflight_existing_file(&path).unwrap();
    drop(open_existing_read_only(&path).unwrap());

    assert!(!sidecar_path(&path, "-wal").exists());
    assert!(!sidecar_path(&path, "-shm").exists());
}

#[cfg(unix)]
#[test]
fn validated_open_supports_owner_private_database_without_sidecars() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime_root = temporary.path().join("runtime");
    let daemon_dir = runtime_root.join("gocode-daemon");
    fs::create_dir_all(&daemon_dir).unwrap();
    fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let path = daemon_dir.join("event-log.db");
    let connection = Connection::open(&path).unwrap();
    apply_migrations(&connection).unwrap();
    drop(connection);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    assert!(
        open_existing_with_pragmas_validated(&path, |_| Ok(())).is_err(),
        "a group/world-writable runtime parent must fail closed"
    );
    fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o755)).unwrap();

    let unsafe_wal = sidecar_path(&path, "-wal");
    assert!(
        open_existing_with_pragmas_validated(&path, |_| {
            fs::write(&unsafe_wal, [1]).unwrap();
            fs::set_permissions(&unsafe_wal, fs::Permissions::from_mode(0o644)).unwrap();
            Ok(())
        })
        .is_err(),
        "a sidecar introduced during validation must be revalidated"
    );
    if unsafe_wal.exists() {
        fs::remove_file(&unsafe_wal).unwrap();
    }

    let validated = open_existing_with_pragmas_validated(&path, |connection| {
        let query_only: i64 =
            connection.pragma_query_value(None, "query_only", |row| row.get(0))?;
        assert_eq!(query_only, 1);
        Ok(())
    })
    .unwrap();
    validated
        .execute(
            "INSERT INTO _daemon_info (key, value) VALUES ('validated-no-sidecar', '1')",
            [],
        )
        .unwrap();
}

#[cfg(unix)]
#[test]
fn validated_hot_wal_open_is_connection_scoped_and_writable_after_validation() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime_root = temporary.path().join("runtime");
    let daemon_dir = runtime_root.join("gocode-daemon");
    fs::create_dir_all(&daemon_dir).unwrap();
    fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let path = daemon_dir.join("event-log.db");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
    apply_migrations(&writer).unwrap();
    let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    reader
        .execute_batch("BEGIN; SELECT * FROM schema_version;")
        .unwrap();
    writer
        .execute(
            "INSERT INTO _daemon_info (key, value) VALUES ('protected-test-hot-wal', '1')",
            [],
        )
        .unwrap();
    for file in [
        path.clone(),
        sidecar_path(&path, "-wal"),
        sidecar_path(&path, "-shm"),
    ] {
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    assert!(preflight_existing_file(&path).is_err());
    let validated = open_existing_with_pragmas_validated(&path, |connection| {
        let query_only: i64 =
            connection.pragma_query_value(None, "query_only", |row| row.get(0))?;
        assert_eq!(query_only, 1);
        assert!(
            connection
                .execute(
                    "INSERT INTO _daemon_info (key, value) VALUES ('must-not-write', '1')",
                    []
                )
                .is_err()
        );
        let value: String = connection.query_row(
            "SELECT value FROM _daemon_info WHERE key = 'protected-test-hot-wal'",
            [],
            |row| row.get(0),
        )?;
        if value == "1" {
            Ok(())
        } else {
            Err(rusqlite::Error::InvalidQuery)
        }
    })
    .unwrap();
    let query_only: i64 = validated
        .pragma_query_value(None, "query_only", |row| row.get(0))
        .unwrap();
    assert_eq!(query_only, 0);
    validated
        .execute(
            "INSERT INTO _daemon_info (key, value) VALUES ('validated-writer', '1')",
            [],
        )
        .unwrap();
    assert!(preflight_existing_file(&path).is_err());
    assert!(open_existing_read_only(&path).is_err());
    assert!(open_with_pragmas(path.to_str().unwrap()).is_err());
}

#[cfg(unix)]
#[test]
fn rejected_validated_open_leaves_default_openers_fail_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime_root = temporary.path().join("runtime");
    let daemon_dir = runtime_root.join("gocode-daemon");
    fs::create_dir_all(&daemon_dir).unwrap();
    fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let path = daemon_dir.join("event-log.db");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
    apply_migrations(&writer).unwrap();
    let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    reader
        .execute_batch("BEGIN; SELECT * FROM schema_version;")
        .unwrap();
    writer
        .execute(
            "INSERT INTO _daemon_info (key, value) VALUES ('hot-wal', '1')",
            [],
        )
        .unwrap();
    for file in [
        path.clone(),
        sidecar_path(&path, "-wal"),
        sidecar_path(&path, "-shm"),
    ] {
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    assert!(
        open_existing_with_pragmas_validated(&path, |connection| {
            let query_only: i64 =
                connection.pragma_query_value(None, "query_only", |row| row.get(0))?;
            assert_eq!(query_only, 1);
            assert!(
                connection
                    .execute_batch("CREATE TABLE rejected_validation (id INTEGER);")
                    .is_err()
            );
            Err(rusqlite::Error::InvalidQuery)
        })
        .is_err()
    );
    let rejected_table: bool = writer
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'rejected_validation')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!rejected_table);
    assert!(preflight_existing_file(&path).is_err());
    assert!(open_existing_read_only(&path).is_err());
    assert!(open_with_pragmas(path.to_str().unwrap()).is_err());
}

#[cfg(unix)]
#[test]
fn validated_open_rejects_path_replacement_during_validation() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime_root = temporary.path().join("runtime");
    let daemon_dir = runtime_root.join("gocode-daemon");
    fs::create_dir_all(&daemon_dir).unwrap();
    fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let path = daemon_dir.join("event-log.db");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
    apply_migrations(&writer).unwrap();
    let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    reader
        .execute_batch("BEGIN; SELECT * FROM schema_version;")
        .unwrap();
    writer
        .execute(
            "INSERT INTO _daemon_info (key, value) VALUES ('hot-wal', '1')",
            [],
        )
        .unwrap();
    for file in [
        path.clone(),
        sidecar_path(&path, "-wal"),
        sidecar_path(&path, "-shm"),
    ] {
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let original = daemon_dir.join("original-event-log.db");
    assert!(
        open_existing_with_pragmas_validated(&path, |_| {
            fs::rename(&path, &original).unwrap();
            fs::write(&path, [1]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            Ok(())
        })
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn protected_recovery_rejects_non_private_or_linked_file_sets() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime_root = temporary.path().join("runtime");
    let daemon_dir = runtime_root.join("gocode-daemon");
    fs::create_dir_all(&daemon_dir).unwrap();
    fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let path = daemon_dir.join("event-log.db");
    fs::write(&path, [1]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let unrelated = daemon_dir.join("unrelated");
    fs::write(&unrelated, [2]).unwrap();
    fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&unrelated, sidecar_path(&path, "-wal")).unwrap();

    assert!(
        open_existing_with_pragmas_validated(&path, |_| Ok(())).is_err(),
        "a linked WAL must fail before SQLite admission"
    );
    fs::remove_file(sidecar_path(&path, "-wal")).unwrap();
    std::os::unix::fs::symlink(daemon_dir.join("missing"), sidecar_path(&path, "-wal")).unwrap();
    fs::write(sidecar_path(&path, "-shm"), [4]).unwrap();
    fs::set_permissions(
        sidecar_path(&path, "-shm"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(
        open_existing_with_pragmas_validated(&path, |_| Ok(())).is_err(),
        "a dangling sidecar link must fail before SQLite admission"
    );
    fs::remove_file(sidecar_path(&path, "-wal")).unwrap();
    fs::remove_file(sidecar_path(&path, "-shm")).unwrap();
    fs::write(sidecar_path(&path, "-wal"), [3]).unwrap();
    fs::set_permissions(
        sidecar_path(&path, "-wal"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(
        open_existing_with_pragmas_validated(&path, |_| Ok(())).is_err(),
        "a group/world-readable WAL must fail before SQLite admission"
    );
}
