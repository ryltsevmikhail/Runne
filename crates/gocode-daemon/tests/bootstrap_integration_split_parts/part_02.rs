#[test]
fn recovery_blocked_state() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);

    // Bootstrap to create the DB
    let o1 = bootstrap(&config).unwrap();
    drop(o1);

    // Insert a synthetic event through a raw connection
    let conn = schema::open_with_pragmas(&config.db_path).unwrap();

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
    drop(o1);

    // Simulate a production-v1 install: DB + legacy bearer, no replay key.
    remove_sidecar_migration_marker(&config);
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
    drop(initial);
    remove_sidecar_migration_marker(&config);

    let legacy_authority = [0x42; 16];
    let connection = schema::open_with_pragmas(&config.db_path).unwrap();
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
