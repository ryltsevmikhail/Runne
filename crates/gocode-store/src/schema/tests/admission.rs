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
    fn protected_recovery_admits_only_an_exact_owner_private_hot_wal_identity() {
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
        assert!(
            with_protected_recovery_read_only_admission(&path, |_| {
                Err(rusqlite::Error::InvalidQuery)
            })
            .is_err()
        );
        assert!(preflight_existing_file(&path).is_err());

        with_protected_recovery_read_only_admission(&path, |connection| {
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
        preflight_existing_file(&path).unwrap();
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
            with_protected_recovery_read_only_admission(&path, |_| Ok(())).is_err(),
            "a linked WAL must fail before SQLite admission"
        );
        fs::remove_file(sidecar_path(&path, "-wal")).unwrap();
        std::os::unix::fs::symlink(daemon_dir.join("missing"), sidecar_path(&path, "-wal"))
            .unwrap();
        fs::write(sidecar_path(&path, "-shm"), [4]).unwrap();
        fs::set_permissions(
            sidecar_path(&path, "-shm"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(
            with_protected_recovery_read_only_admission(&path, |_| Ok(())).is_err(),
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
            with_protected_recovery_read_only_admission(&path, |_| Ok(())).is_err(),
            "a group/world-readable WAL must fail before SQLite admission"
        );
    }

    #[cfg(unix)]
    #[test]
    fn admitted_database_identity_does_not_follow_path_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("event-log.db");
        fs::write(&path, [1]).unwrap();
        admit_identity(&path).unwrap();
        assert!(identity_is_admitted(&path).unwrap());

        fs::rename(&path, temporary.path().join("original.db")).unwrap();
        fs::write(&path, [2]).unwrap();
        assert!(
            !identity_is_admitted(&path).unwrap(),
            "admission must bind the file identity, not only its path"
        );
    }
