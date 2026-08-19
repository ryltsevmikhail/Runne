#[test]
fn recovery_blocked_state() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // Bootstrap to create the DB
    let o1 = bootstrap(&config).unwrap();
    let authority_id = o1.authority_id;
    drop(o1);

    // Insert a synthetic event through a raw connection
    let conn = schema::reopen_managed_connection_validated(
        Path::new(&config.db_path),
        schema::ConnectionMode::ValidatedReopen,
        |connection| {
            if schema::read_authority_id(connection)? == Some(authority_id) {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        },
    )
    .unwrap();
    schema::readiness_from_managed(&conn).unwrap();
    schema::publication_from_managed(&conn).unwrap();

    // Need to satisfy FK constraints
    conn.execute(
        "INSERT OR IGNORE INTO aggregate_streams
         (aggregate_type, aggregate_id, current_version, created_at)
         VALUES (1, x'00000000000000000000000000000042', 1, 0)",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO events
         (event_id, aggregate_type, aggregate_id, sequence, global_position,
          timestamp, sensitivity, schema_version, command_id, idempotency_key,
          actor, payload, integrity_digest, correlation_id, correlation_type,
          integrity_profile)
         VALUES
         (randomblob(16), 1, x'00000000000000000000000000000042', 1, 1,
          0, 0, 1, randomblob(16), x'01', x'02', x'03', randomblob(32),
          randomblob(16), 1, 1)",
        [],
    )
    .unwrap();

    let state = enumerate_recovery_tasks(&conn).unwrap();
    assert_eq!(state, RecoveryState::RecoveryBlocked);
}

// ── 9. empty_db_recovery_ready ──────────────────────────────────────
#[test]
fn empty_db_recovery_ready() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // Fresh bootstrap — DB should be empty of events
    let outcome = bootstrap(&config).unwrap();

    let state = enumerate_recovery_tasks(&outcome.db_conn).unwrap();
    assert_eq!(state, RecoveryState::Ready);
}

// ── 10. replay_key_missing_for_existing_db_is_provisioned ───────────
#[test]
fn replay_key_missing_for_existing_db_is_provisioned_without_legacy_token_reuse() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // Bootstrap once to create DB + replay-integrity key
    let o1 = bootstrap(&config).unwrap();
    let authority_id = o1.authority_id;
    drop(o1);

    // Simulate a production-v1 install: DB + legacy bearer, no replay key.
    remove_sidecar_migration_marker(&config, authority_id);
    fs::remove_file(replay_key_path(&config)).unwrap();
    let legacy_token_path = replay_key_path(&config).with_file_name("token.json");
    let legacy_token = [0x2a; 32];
    fs::write(&legacy_token_path, legacy_token).unwrap();

    let outcome = bootstrap(&config).expect("add-only replay key provision");
    let provisioned = fs::read(replay_key_path(&config)).expect("provisioned replay key");
    assert_eq!(provisioned.len(), 32);
    assert_ne!(provisioned, legacy_token);
    assert_eq!(fs::read(legacy_token_path).unwrap(), legacy_token);
    assert_ne!(
        outcome
            .replay_integrity_key
            .derive_hmac(b"upgrade-evidence"),
        [0; 32]
    );
}

#[test]
fn replay_key_deleted_after_migration_fails_closed_without_replacement() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let initial = bootstrap(&config).unwrap();
    drop(initial);
    fs::remove_file(replay_key_path(&config)).unwrap();

    assert!(bootstrap(&config).is_err());
    assert!(!replay_key_path(&config).exists());
}

#[test]
fn local_session_authority_deleted_after_migration_fails_closed_without_replacement() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let initial = bootstrap(&config).unwrap();
    let initial_authority = initial.authority_id;
    drop(initial);
    remove_sidecar_migration_marker(&config, initial_authority);

    let legacy_authority = [0x42; 16];
    let connection = schema::reopen_managed_connection_validated(
        Path::new(&config.db_path),
        schema::ConnectionMode::ValidatedReopen,
        |connection| {
            if schema::read_authority_id(connection)? == Some(initial_authority) {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        },
    )
    .unwrap();
    schema::readiness_from_managed(&connection).unwrap();
    schema::publication_from_managed(&connection).unwrap();
    connection
        .execute(
            "UPDATE _authority SET authority_id = ?1 WHERE id = 1",
            rusqlite::params![legacy_authority.as_slice()],
        )
        .unwrap();
    drop(connection);
    let database_path = db_path(&config);
    let locks =
        LockSet::acquire_path(&database_path, runtime_dir(daemon_dir(&database_path))).unwrap();
    locks.write_metadata(&legacy_authority).unwrap();
    drop(locks);
    let _ = fs::remove_file(local_session_authority_path(&config));

    let migrated = bootstrap(&config).expect("first migration provisions authority sidecar");
    drop(migrated);
    let authority_path = local_session_authority_path(&config);
    assert!(authority_path.exists());
    fs::remove_file(&authority_path).unwrap();

    assert!(bootstrap(&config).is_err());
    assert!(!authority_path.exists());
}

#[test]
fn invalid_existing_local_session_authority_fails_closed_without_rewrite() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let initial = bootstrap(&config).unwrap();
    drop(initial);
    let path = local_session_authority_path(&config);
    let marker = b"invalid-authority";
    fs::write(&path, marker).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    assert!(bootstrap(&config).is_err());
    assert_eq!(fs::read(path).unwrap(), marker);
}

#[test]
fn malformed_lock_metadata_is_repaired_from_the_locked_existing_database() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let initial = bootstrap(&config).unwrap();
    let authority_id = initial.authority_id;
    drop(initial);

    let database_path = db_path(&config);
    let locks =
        LockSet::acquire_path(&database_path, runtime_dir(daemon_dir(&database_path))).unwrap();
    let mut metadata = locks.path_lock.file();
    metadata.set_len(0).unwrap();
    metadata.write_all(b"torn-metadata").unwrap();
    metadata.sync_all().unwrap();
    drop(locks);

    let repaired = bootstrap(&config).unwrap();
    assert_eq!(repaired.authority_id, authority_id);
    assert_eq!(
        repaired.locks.read_metadata_snapshot().unwrap(),
        runne_daemon::lock::MetadataSnapshot::Valid { authority_id }
    );
}

#[test]
fn bootstrap_rejects_candidate_schema_before_wal_or_main_db_mutation() {
    for version in [9, 10, 11] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let initial = bootstrap(&config).unwrap();
        drop(initial);
        let db = db_path(&config);
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", db.display()));
        }
        let connection = Connection::open(&db).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
                 CREATE TABLE candidate_data (value TEXT NOT NULL);
                 INSERT INTO candidate_data VALUES ('unchanged');",
            )
            .unwrap();
        connection
            .execute("INSERT INTO schema_version VALUES (?1)", [version])
            .unwrap();
        drop(connection);
        let before = fs::read(&db).unwrap();

        assert!(bootstrap(&config).is_err(), "candidate V{version}");
        assert_eq!(fs::read(&db).unwrap(), before);
        assert!(!PathBuf::from(format!("{}-wal", db.display())).exists());
        assert!(!PathBuf::from(format!("{}-shm", db.display())).exists());
    }
}

#[cfg(unix)]
#[test]
fn authority_lock_conflict_rejects_a_clone_before_writable_bootstrap_changes() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let initial = bootstrap(&config).unwrap();
    drop(initial);

    let original = db_path(&config);
    let clone = daemon_dir(&original).join("event-log-clone.db");
    fs::copy(&original, &clone).unwrap();
    let before = fs::read(&clone).unwrap();
    let mut clone_defaults = BuiltInDefaults::new(temp.path());
    clone_defaults.db_path = clone.display().to_string();
    let clone_config = ConfigurationSnapshot::from_defaults(&clone_defaults);

    let holder = bootstrap(&config).unwrap();
    let rejected = bootstrap(&clone_config).unwrap_err();
    assert!(rejected.to_string().contains("open DB"));
    assert_eq!(fs::read(&clone).unwrap(), before);
    assert!(!PathBuf::from(format!("{}-wal", clone.display())).exists());
    assert!(!PathBuf::from(format!("{}-shm", clone.display())).exists());
    drop(holder);
}

#[cfg(unix)]
#[test]
fn validated_reopen_retains_bootstrap_authority_lock() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    drop(bootstrap(&config).unwrap());

    let reopened = bootstrap(&config).unwrap();
    assert!(reopened.locks.authority_lock.is_some());
    let authority_id = reopened.authority_id;
    let competitor_path = temp.path().join("authority-lock-competitor.db");
    fs::File::create(&competitor_path).unwrap();
    let mut competitor = LockSet::acquire_path(&competitor_path, temp.path()).unwrap();

    assert!(
        competitor
            .acquire_authority_lock(&authority_id, temp.path())
            .is_err(),
        "a competing authority lock must fail while BootstrapOutcome is alive"
    );
    assert!(competitor.authority_lock.is_none());
    runne_store::schema::readiness_from_managed(&reopened.db_conn).unwrap();
    runne_store::schema::publication_from_managed(&reopened.db_conn).unwrap();
    drop(reopened);
    competitor
        .acquire_authority_lock(&authority_id, temp.path())
        .expect("dropping BootstrapOutcome must release its authority lock");
    assert!(competitor.authority_lock.is_some());
}
