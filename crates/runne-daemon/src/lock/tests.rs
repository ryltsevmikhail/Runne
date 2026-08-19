    use super::*;
    use tempfile::TempDir;

    /// Helper: create a runtime dir with an empty runne-daemon subdir.
    fn runtime_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("runne-daemon")).unwrap();
        dir
    }

    /// Helper: create a dummy file (act as DB path).
    fn dummy_db_file(dir: &TempDir) -> PathBuf {
        let path = dir.path().join("event-log.db");
        fs::File::create(&path).unwrap();
        path
    }

    #[test]
    fn acquire_path_creates_lock() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let locks = LockSet::acquire_path(&db, rt.path()).unwrap();
        // Check the lock file was created
        let canonical = canonicalize_path(&db).unwrap();
        let hash = sha256_hex(canonical.to_str().unwrap().as_bytes());
        let lock_path = rt
            .path()
            .join("runne-daemon")
            .join(format!("path-{hash}.lock"));
        assert!(lock_path.exists());
        // Metadata should be Empty (new file, no write yet)
        let snap = locks.read_metadata_snapshot().unwrap();
        assert_eq!(snap, MetadataSnapshot::Empty);
    }

    #[test]
    fn acquire_path_conflict() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let _locks1 = LockSet::acquire_path(&db, rt.path()).unwrap();
        let result2 = LockSet::acquire_path(&db, rt.path());
        assert!(result2.is_err());
        let msg = format!("{}", result2.unwrap_err());
        assert!(
            msg.contains("lock error") || msg.contains("WouldBlock") || msg.contains("resource"),
            "got: {msg}"
        );
    }

    #[test]
    fn read_metadata_empty() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let locks = LockSet::acquire_path(&db, rt.path()).unwrap();
        let snap = locks.read_metadata_snapshot().unwrap();
        assert_eq!(snap, MetadataSnapshot::Empty);
    }

    #[test]
    fn write_and_read_metadata() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let locks = LockSet::acquire_path(&db, rt.path()).unwrap();
        let aid: [u8; 16] = [0xAA; 16];
        locks.write_metadata(&aid).unwrap();
        let snap = locks.read_metadata_snapshot().unwrap();
        assert_eq!(snap, MetadataSnapshot::Valid { authority_id: aid });
    }

    #[test]
    fn metadata_different_paths_independent() {
        let rt = runtime_dir();
        let db1 = rt.path().join("db1.db");
        fs::File::create(&db1).unwrap();
        let db2 = rt.path().join("db2.db");
        fs::File::create(&db2).unwrap();

        let locks1 = LockSet::acquire_path(&db1, rt.path()).unwrap();
        let locks2 = LockSet::acquire_path(&db2, rt.path()).unwrap();

        // Different locks should have different lock files
        let c1 = canonicalize_path(&db1).unwrap();
        let c2 = canonicalize_path(&db2).unwrap();
        assert_ne!(c1, c2);

        // Both should be Empty
        assert_eq!(
            locks1.read_metadata_snapshot().unwrap(),
            MetadataSnapshot::Empty
        );
        assert_eq!(
            locks2.read_metadata_snapshot().unwrap(),
            MetadataSnapshot::Empty
        );
    }

    #[test]
    fn file_identity_lock() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let mut locks = LockSet::acquire_path(&db, rt.path()).unwrap();

        let file = fs::File::open(&db).unwrap();
        locks.acquire_file_lock(&file, rt.path()).unwrap();
        assert!(locks.file_lock.is_some());
    }

    #[test]
    fn authority_lock() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let mut locks = LockSet::acquire_path(&db, rt.path()).unwrap();

        let aid: [u8; 16] = [0xBB; 16];
        locks.acquire_authority_lock(&aid, rt.path()).unwrap();
        assert!(locks.authority_lock.is_some());
    }

    #[test]
    fn malformed_metadata_detected() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let locks = LockSet::acquire_path(&db, rt.path()).unwrap();

        // Write garbage to the lock file (simulate torn write)
        use std::io::Write;
        let mut file = locks.path_lock.file();
        file.set_len(0).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&[0xFFu8; 25]).unwrap();
        file.sync_all().unwrap();

        let snap = locks.read_metadata_snapshot().unwrap();
        assert_eq!(snap, MetadataSnapshot::Malformed);
    }

    #[test]
    fn lock_released_on_drop() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);

        {
            let _locks = LockSet::acquire_path(&db, rt.path()).unwrap();
        }
        // Should be able to re-acquire after drop
        let locks2 = LockSet::acquire_path(&db, rt.path());
        assert!(locks2.is_ok());
    }

    #[test]
    fn concurrent_lock_conflict() {
        use std::thread;

        let rt = runtime_dir();
        let db = dummy_db_file(&rt);

        let _locks = LockSet::acquire_path(&db, rt.path()).unwrap();

        let rt_path = rt.path().to_path_buf();
        let db_path = db.clone();

        let handle = thread::spawn(move || LockSet::acquire_path(&db_path, &rt_path));

        let result = handle.join().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn hardlink_same_identity() {
        let rt = runtime_dir();
        let db1 = rt.path().join("original.db");
        fs::File::create(&db1).unwrap();
        let db2 = rt.path().join("hardlink.db");

        // Create hardlink
        fs::hard_link(&db1, &db2).unwrap();

        let f1 = fs::File::open(&db1).unwrap();
        let f2 = fs::File::open(&db2).unwrap();

        let id1 = platform_file_identity(&f1).unwrap();
        let id2 = platform_file_identity(&f2).unwrap();

        assert_eq!(
            id1, id2,
            "hardlinked files must have the same platform identity"
        );
    }
