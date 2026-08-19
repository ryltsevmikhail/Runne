    use super::*;
    use rusqlite::{OpenFlags, params};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    fn td(b: u8) -> VerificationDigest {
        VerificationDigest::from_bytes([b; 32])
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FileState {
        main_bytes: Vec<u8>,
        journal_mode: String,
        sidecars: [bool; 2],
        #[cfg(unix)]
        mode: u32,
    }

    fn file_state(path: &Path) -> FileState {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let journal_mode = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        drop(conn);

        FileState {
            main_bytes: fs::read(path).unwrap(),
            journal_mode,
            sidecars: [
                path.with_added_extension("sqlite-wal").exists(),
                path.with_added_extension("sqlite-shm").exists(),
            ],
            #[cfg(unix)]
            mode: {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(path).unwrap().permissions().mode() & 0o777
            },
        }
    }

    #[test]
    fn file_backed_stores_reject_unsupported_schema_before_mutation() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for (name, user_version, provenance) in [
            ("future", 10, "future-v10"),
            ("candidate", 9, "candidate-v9"),
        ] {
            let path = std::env::temp_dir().join(format!(
                "runne-{name}-schema-{}-{nonce}.sqlite",
                std::process::id()
            ));
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')));
                 CREATE TABLE schema_lineage (schema_version INTEGER PRIMARY KEY, provenance TEXT NOT NULL);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [user_version],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO schema_lineage (schema_version, provenance) VALUES (?1, ?2)",
                (user_version, provenance),
            )
            .unwrap();
            conn.pragma_update(None, "user_version", user_version)
                .unwrap();
            drop(conn);

            let initial = file_state(&path);
            assert!(SqliteIntentStore::open(&path).is_err());
            assert_eq!(file_state(&path), initial);
            assert!(crate::verification::evidence_store::SqliteEvidenceStore::open(&path).is_err());
            assert_eq!(file_state(&path), initial);

            for suffix in ["", "-wal", "-shm"] {
                let _ = fs::remove_file(format!("{}{suffix}", path.display()));
            }
        }
    }

    #[test]
    fn intent_full_lifecycle() {
        let store = SqliteIntentStore::open_in_memory().unwrap();
        let id = Uuid::now_v7();
        let intent = store.reserve(id, "key1", td(1), td(2)).unwrap();
        store
            .claim_dispatching(&id, &intent.integrity_digest)
            .unwrap();
        store.settle(&id, true).unwrap();
    }

    #[test]
    fn duplicate_same_key_with_changed_inputs_conflicts_and_preserves_original() {
        let store = SqliteIntentStore::open_in_memory().unwrap();
        let id = Uuid::now_v7();
        let original = store.reserve(id, "key", td(1), td(2)).unwrap();
        assert!(matches!(
            store.reserve(id, "key", td(3), td(2)),
            Err(IntentError::IdempotencyConflict)
        ));
        assert_eq!(
            store
                .reserve(id, "key", td(1), td(2))
                .unwrap()
                .integrity_digest,
            original.integrity_digest
        );
    }

    #[test]
    fn duplicate_different_id_same_key_conflicts() {
        let store = SqliteIntentStore::open_in_memory().unwrap();
        store.reserve(Uuid::now_v7(), "key", td(1), td(2)).unwrap();
        assert!(matches!(
            store.reserve(Uuid::now_v7(), "key", td(1), td(2)),
            Err(IntentError::IdempotencyConflict)
        ));
    }

    #[test]
    fn wrong_or_zero_digest_cannot_claim() {
        let store = SqliteIntentStore::open_in_memory().unwrap();
        let id = Uuid::now_v7();
        let intent = store.reserve(id, "key", td(1), td(2)).unwrap();
        assert_ne!(intent.integrity_digest, td(0));
        assert!(matches!(
            store.claim_dispatching(&id, &td(0)),
            Err(IntentError::DigestMismatch)
        ));
        assert!(matches!(
            store.claim_dispatching(&id, &td(9)),
            Err(IntentError::DigestMismatch)
        ));
        store
            .claim_dispatching(&id, &intent.integrity_digest)
            .unwrap();
    }

    #[test]
    fn conditional_claim_allows_exactly_one_winner() {
        let store = SqliteIntentStore::open_in_memory().unwrap();
        let id = Uuid::now_v7();
        let intent = store.reserve(id, "key", td(1), td(2)).unwrap();
        assert!(
            store
                .claim_dispatching(&id, &intent.integrity_digest)
                .is_ok()
        );
        assert!(matches!(
            store.claim_dispatching(&id, &intent.integrity_digest),
            Err(IntentError::InvalidTransition)
        ));
    }

    #[test]
    fn malformed_row_returns_corrupt_store_not_zero_identity_or_digest() {
        let store = SqliteIntentStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        conn.execute(
            "INSERT INTO consumption_intents VALUES (?1, 'bad', 'Reserved', ?2, ?2, ?2)",
            params![vec![1_u8; 15], vec![2_u8; 31]],
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            store.reserve(Uuid::now_v7(), "bad", td(1), td(2)),
            Err(IntentError::CorruptStore)
        ));
    }

    #[test]
    fn tampered_valid_length_digest_is_corrupt_not_reusable_claim_or_replay() {
        let store = SqliteIntentStore::open_in_memory().unwrap();
        let id = Uuid::now_v7();
        let intent = store.reserve(id, "key", td(1), td(2)).unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "UPDATE consumption_intents SET integrity_digest = ?1 WHERE intent_id = ?2",
            params![[0xA5_u8; 32].as_slice(), id.as_bytes()],
        )
        .unwrap();
        drop(conn);

        assert!(matches!(
            store.claim_dispatching(&id, &intent.integrity_digest),
            Err(IntentError::CorruptStore)
        ));
        assert!(matches!(
            store.reserve(id, "key", td(1), td(2)),
            Err(IntentError::CorruptStore)
        ));
    }

    #[test]
    fn invalidation_and_reconciliation_do_not_silently_accept_conflicts() {
        let store = SqliteIntentStore::open_in_memory().unwrap();
        let id = Uuid::now_v7();
        let intent = store.reserve(id, "key", td(1), td(2)).unwrap();
        store.invalidate(&id).unwrap();
        assert!(matches!(
            store.settle(&id, true),
            Err(IntentError::InvalidTransition)
        ));
        assert!(matches!(
            store.reconcile(&id, &DispatchEvidence::NotStarted),
            Err(IntentError::InvalidTransition)
        ));
        assert!(matches!(
            store.claim_dispatching(&id, &intent.integrity_digest),
            Err(IntentError::IntentInvalidated)
        ));
    }
