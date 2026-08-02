    use super::*;
    use crate::config::BuiltInDefaults;
    use tempfile::TempDir;

    /// Build a `ConfigurationSnapshot` rooted at a temp dir.
    fn test_config(temp: &TempDir) -> ConfigurationSnapshot {
        let defaults = BuiltInDefaults::new(temp.path());
        ConfigurationSnapshot::from_defaults(&defaults)
    }

    // ── 1. first_start_creates_db_and_replay_key ────────────────
    #[test]
    fn first_start_creates_db_and_replay_key() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        let outcome = bootstrap(&config).unwrap();

        assert!(!outcome.db_existed);
        assert_eq!(outcome.startup_mode, StartupMode::FirstStart);
        assert!(PathBuf::from(&config.db_path).exists());
        assert!(PathBuf::from(&config.replay_integrity_key_path).exists());
        // file_lock is only acquired for existing DBs (no hardlink
        // risk on a fresh create); authority_lock must be held.
        assert!(outcome.locks.authority_lock.is_some());
    }

    // ── 2. restart_reuses_existing_db ──────────────────────────
    #[test]
    fn restart_reuses_existing_db() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // First bootstrap
        let o1 = bootstrap(&config).unwrap();
        assert!(!o1.db_existed);
        assert_eq!(o1.startup_mode, StartupMode::FirstStart);
        let aid1 = o1.authority_id;
        drop(o1);

        // Second bootstrap — must find existing DB
        let o2 = bootstrap(&config).unwrap();
        assert!(o2.db_existed);
        assert_eq!(o2.startup_mode, StartupMode::Restart);
        assert_eq!(o2.authority_id, aid1);
    }

    // ── 3. crash_before_metadata_publish_is_repaired ────────────
    #[test]
    fn crash_before_metadata_publish_is_repaired() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // Step 1: do a full bootstrap to create the DB + authority
        let o1 = bootstrap(&config).unwrap();
        let aid = o1.authority_id;
        drop(o1);

        // Step 2: simulate crash by clearing lock metadata
        // We need to acquire the lock, clear metadata, release.
        let db_path = PathBuf::from(&config.db_path);
        let daemon_dir = db_path.parent().unwrap();
        let runtime_dir = daemon_dir.parent().unwrap();

        {
            let locks = LockSet::acquire_path(&db_path, runtime_dir).unwrap();
            // Truncate the metadata to zero bytes
            let f = locks.path_lock.file();
            f.set_len(0).unwrap();
            f.sync_all().unwrap();
        }

        // Step 3: bootstrap again — must repair metadata, not error
        let o2 = bootstrap(&config).unwrap();
        assert!(o2.db_existed);
        assert_eq!(o2.startup_mode, StartupMode::Restart);
        assert_eq!(o2.authority_id, aid);
    }

    // ── 4. authority_mismatch_causes_exit5 ──────────────────────
    #[test]
    fn authority_mismatch_causes_exit5() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // Full bootstrap to create state
        let o1 = bootstrap(&config).unwrap();
        drop(o1);

        // Write a different authority into lock metadata
        let db_path = PathBuf::from(&config.db_path);
        let daemon_dir = db_path.parent().unwrap();
        let runtime_dir = daemon_dir.parent().unwrap();
        let wrong_aid: [u8; 16] = [0xDE; 16];

        {
            let locks = LockSet::acquire_path(&db_path, runtime_dir).unwrap();
            locks.write_metadata(&wrong_aid).unwrap();
        }

        // Bootstrap must fail with Bootstrap error
        let result = bootstrap(&config);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("authority mismatch") || msg.contains("bootstrap error"),
            "expected authority mismatch, got: {msg}"
        );
    }

    // ── 5. published_authority_without_db_causes_exit5 ──────────
    #[test]
    fn published_authority_without_db_causes_exit5() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        // Manually create metadata *without* the DB file
        let db_path = PathBuf::from(&config.db_path);
        let daemon_dir = db_path.parent().unwrap();
        let runtime_dir = daemon_dir.parent().unwrap();

        // Create daemon dir (so lock file can be stored)
        fs::create_dir_all(daemon_dir).unwrap();

        let fake_aid: [u8; 16] = [0xFA; 16];
        {
            // We need the DB file to exist for lock acquisition
            fs::File::create(&db_path).unwrap();
            let locks = LockSet::acquire_path(&db_path, runtime_dir).unwrap();
            locks.write_metadata(&fake_aid).unwrap();
            // Close lock, remove DB file, but leave metadata
        }
        fs::remove_file(&db_path).unwrap();

        // Bootstrap must fail because metadata exists but DB is gone
        let result = bootstrap(&config);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("bootstrap error") || msg.contains("authority"),
            "expected authority-without-db error, got: {msg}"
        );
    }

    // ── 6. restart_with_existing_replay_key_loads_correctly ─────
    #[test]
    fn restart_with_existing_replay_key_loads_correctly() {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);

        let o1 = bootstrap(&config).unwrap();
        let marker = o1.replay_integrity_key.derive_hmac(b"persistence-test");
        drop(o1);

        let o2 = bootstrap(&config).unwrap();
        assert_eq!(
            o2.replay_integrity_key.derive_hmac(b"persistence-test"),
            marker,
            "replay-integrity key must persist across restarts"
        );
    }

    // ── 7. concurrent_first_start_fails ─────────────────────────
    #[test]
    fn concurrent_first_start_fails() {
        use std::thread;

        let temp = TempDir::new().unwrap();
        let config1 = test_config(&temp);

        // First bootstrap holds the path lock
        let _o1 = bootstrap(&config1).unwrap();

        // Second bootstrap must fail (lock conflict)
        let temp_path = temp.path().to_path_buf();
        let handle = thread::spawn(move || {
            let config2 = {
                let defaults = BuiltInDefaults::new(&temp_path);
                ConfigurationSnapshot::from_defaults(&defaults)
            };
            bootstrap(&config2)
        });

        let result = handle.join().unwrap();
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("bootstrap error") || msg.contains("lock"),
            "expected lock conflict, got: {msg}"
        );
    }
