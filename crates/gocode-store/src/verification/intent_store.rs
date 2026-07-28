use std::path::Path;
use std::sync::{Arc, Mutex};

use gocode_domain::verification::digest::VerificationDigest;
use gocode_domain::verification::evaluation::IntentError;
use gocode_domain::verification::identity::*;
use gocode_domain::verification::intent::{ConsumptionIntent, DispatchEvidence, IntentState};
use rusqlite::{Connection, Error as SqliteError, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::schema;

/// SQLite-backed intent store with durable, conditional state transitions.
#[derive(Clone)]
pub struct SqliteIntentStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteIntentStore {
    /// Open a durable intent store using the canonical schema migrations.
    pub fn open(db_path: &Path) -> Result<Self, rusqlite::Error> {
        schema::preflight_existing_file(db_path)?;
        let conn = schema::open_with_pragmas(&db_path.to_string_lossy())?;
        schema::apply_migrations(&conn)?;
        schema::run_startup_gates(&conn, &db_path.to_string_lossy())?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory intent store using the canonical schema migrations.
    #[doc(hidden)]
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        schema::apply_migrations(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Reserve an intent atomically. Exact duplicate requests replay the prior reservation.
    pub fn reserve(
        &self,
        intent_id: IntentID,
        key: &str,
        snapshot: VerificationDigest,
        target: VerificationDigest,
    ) -> Result<ConsumptionIntent, IntentError> {
        let mut conn = self.conn.lock().map_err(|_| IntentError::CorruptStore)?;
        let tx = immediate_transaction(&mut conn)?;

        let existing_by_id = find_intent(&tx, "intent_id", intent_id.as_bytes())?;
        let existing_by_key = find_intent(&tx, "idempotency_key", key)?;
        if let Some(existing) = existing_by_id.or(existing_by_key) {
            tx.commit().map_err(|_| IntentError::CorruptStore)?;
            if existing.intent_id == intent_id
                && existing.idempotency_key == key
                && existing.gate_head_snapshot_digest == snapshot
                && existing.target_artifact_digest == target
            {
                return Ok(existing);
            }
            return Err(IntentError::IdempotencyConflict);
        }

        let integrity = reservation_digest(&intent_id, key, &snapshot, &target);
        tx.execute(
            "INSERT INTO consumption_intents
             (intent_id, idempotency_key, state, gate_head_snapshot_digest,
              target_artifact_digest, integrity_digest)
             VALUES (?1, ?2, 'Reserved', ?3, ?4, ?5)",
            params![
                intent_id.as_bytes(),
                key,
                snapshot.as_bytes(),
                target.as_bytes(),
                integrity.as_bytes(),
            ],
        )
        .map_err(|_| IntentError::CorruptStore)?;
        tx.commit().map_err(|_| IntentError::CorruptStore)?;

        Ok(ConsumptionIntent {
            intent_id,
            idempotency_key: key.to_owned(),
            state: IntentState::Reserved,
            gate_head_snapshot_digest: snapshot,
            target_artifact_digest: target,
            integrity_digest: integrity,
        })
    }

    /// Atomically claim a reservation when its exact integrity digest still matches.
    pub fn claim_dispatching(
        &self,
        intent_id: &IntentID,
        expected_digest: &VerificationDigest,
    ) -> Result<(), IntentError> {
        let mut conn = self.conn.lock().map_err(|_| IntentError::CorruptStore)?;
        let tx = immediate_transaction(&mut conn)?;
        let intent = find_intent(&tx, "intent_id", intent_id.as_bytes())?
            .ok_or(IntentError::IntentNotFound)?;
        if intent.state == IntentState::Invalidated {
            return Err(IntentError::IntentInvalidated);
        }
        if intent.state != IntentState::Reserved {
            return Err(IntentError::InvalidTransition);
        }
        if intent.integrity_digest != *expected_digest {
            return Err(IntentError::DigestMismatch);
        }
        let affected = tx
            .execute(
                "UPDATE consumption_intents SET state = 'Dispatching'
                 WHERE intent_id = ?1 AND state = 'Reserved' AND integrity_digest = ?2",
                params![intent_id.as_bytes(), expected_digest.as_bytes()],
            )
            .map_err(|_| IntentError::CorruptStore)?;
        if affected != 1 {
            return Err(IntentError::InvalidTransition);
        }
        tx.commit().map_err(|_| IntentError::CorruptStore)
    }

    /// Invalidate a reservation. Repeating the same invalidation is a deterministic replay.
    pub fn invalidate(&self, intent_id: &IntentID) -> Result<(), IntentError> {
        self.transition(intent_id, IntentState::Reserved, IntentState::Invalidated)
    }

    /// Settle a dispatch. Repeating the same terminal outcome is a deterministic replay.
    pub fn settle(&self, intent_id: &IntentID, success: bool) -> Result<(), IntentError> {
        self.transition(
            intent_id,
            IntentState::Dispatching,
            if success {
                IntentState::Completed
            } else {
                IntentState::Failed
            },
        )
    }

    /// Reconcile dispatch evidence without accepting contradictory terminal outcomes.
    pub fn reconcile(
        &self,
        intent_id: &IntentID,
        evidence: &DispatchEvidence,
    ) -> Result<(), IntentError> {
        match evidence {
            DispatchEvidence::NotStarted => {
                self.transition(intent_id, IntentState::Dispatching, IntentState::Abandoned)
            }
            DispatchEvidence::Acknowledged { outcome, .. } => self.transition(
                intent_id,
                IntentState::Dispatching,
                if outcome == "success" {
                    IntentState::Completed
                } else {
                    IntentState::Failed
                },
            ),
            DispatchEvidence::Unknown => {
                let mut conn = self.conn.lock().map_err(|_| IntentError::CorruptStore)?;
                let tx = immediate_transaction(&mut conn)?;
                let intent = find_intent(&tx, "intent_id", intent_id.as_bytes())?
                    .ok_or(IntentError::IntentNotFound)?;
                if intent.state != IntentState::Dispatching {
                    return Err(IntentError::InvalidTransition);
                }
                tx.commit().map_err(|_| IntentError::CorruptStore)
            }
        }
    }

    fn transition(
        &self,
        intent_id: &IntentID,
        from: IntentState,
        to: IntentState,
    ) -> Result<(), IntentError> {
        let mut conn = self.conn.lock().map_err(|_| IntentError::CorruptStore)?;
        let tx = immediate_transaction(&mut conn)?;
        let intent = find_intent(&tx, "intent_id", intent_id.as_bytes())?
            .ok_or(IntentError::IntentNotFound)?;
        if intent.state == to {
            return tx.commit().map_err(|_| IntentError::CorruptStore);
        }
        if intent.state != from {
            return Err(IntentError::InvalidTransition);
        }
        let affected = tx
            .execute(
                "UPDATE consumption_intents SET state = ?1 WHERE intent_id = ?2 AND state = ?3",
                params![state_name(to), intent_id.as_bytes(), state_name(from)],
            )
            .map_err(|_| IntentError::CorruptStore)?;
        if affected != 1 {
            return Err(IntentError::InvalidTransition);
        }
        tx.commit().map_err(|_| IntentError::CorruptStore)
    }
}

fn immediate_transaction(conn: &mut Connection) -> Result<Transaction<'_>, IntentError> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| IntentError::CorruptStore)
}

fn find_intent<P: rusqlite::types::ToSql + ?Sized>(
    tx: &Transaction<'_>,
    column: &str,
    value: &P,
) -> Result<Option<ConsumptionIntent>, IntentError> {
    let sql = format!(
        "SELECT intent_id, idempotency_key, state, gate_head_snapshot_digest,
                target_artifact_digest, integrity_digest
         FROM consumption_intents WHERE {column} = ?1"
    );
    match tx.query_row(&sql, [value], read_intent_row) {
        Ok(intent) => Ok(Some(intent)),
        Err(SqliteError::QueryReturnedNoRows) => Ok(None),
        Err(_) => Err(IntentError::CorruptStore),
    }
}

fn reservation_digest(
    intent_id: &IntentID,
    key: &str,
    snapshot: &VerificationDigest,
    target: &VerificationDigest,
) -> VerificationDigest {
    canonical_reservation_digest(
        intent_id.as_bytes(),
        key,
        snapshot.as_bytes(),
        target.as_bytes(),
    )
}

pub(crate) fn canonical_reservation_digest(
    intent_id: &[u8; 16],
    key: &str,
    snapshot: &[u8; 32],
    target: &[u8; 32],
) -> VerificationDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode-runtime/consumption-intent-reservation/v1\0");
    hasher.update(intent_id);
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key.as_bytes());
    hasher.update(snapshot);
    hasher.update(target);
    VerificationDigest::from_bytes(hasher.finalize().into())
}

fn read_intent_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConsumptionIntent> {
    let intent_id_blob: Vec<u8> = row.get(0)?;
    let snapshot_blob: Vec<u8> = row.get(3)?;
    let target_blob: Vec<u8> = row.get(4)?;
    let integrity_blob: Vec<u8> = row.get(5)?;
    let intent_id = exact_array::<16>(&intent_id_blob)?;
    let snapshot = exact_array::<32>(&snapshot_blob)?;
    let target = exact_array::<32>(&target_blob)?;
    let integrity = exact_array::<32>(&integrity_blob)?;
    let state = match row.get::<_, String>(2)?.as_str() {
        "Reserved" => IntentState::Reserved,
        "Dispatching" => IntentState::Dispatching,
        "Completed" => IntentState::Completed,
        "Failed" => IntentState::Failed,
        "Invalidated" => IntentState::Invalidated,
        "Abandoned" => IntentState::Abandoned,
        _ => return Err(malformed_row()),
    };
    let intent_id = uuid::Uuid::from_bytes(intent_id);
    let idempotency_key: String = row.get(1)?;
    let gate_head_snapshot_digest = VerificationDigest::from_bytes(snapshot);
    let target_artifact_digest = VerificationDigest::from_bytes(target);
    let integrity_digest = VerificationDigest::from_bytes(integrity);
    if integrity_digest
        != reservation_digest(
            &intent_id,
            &idempotency_key,
            &gate_head_snapshot_digest,
            &target_artifact_digest,
        )
    {
        return Err(malformed_row());
    }
    Ok(ConsumptionIntent {
        intent_id,
        idempotency_key,
        state,
        gate_head_snapshot_digest,
        target_artifact_digest,
        integrity_digest,
    })
}

fn exact_array<const N: usize>(value: &[u8]) -> rusqlite::Result<[u8; N]> {
    value.try_into().map_err(|_| malformed_row())
}

fn malformed_row() -> SqliteError {
    SqliteError::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed intent row",
        )),
    )
}

fn state_name(state: IntentState) -> &'static str {
    match state {
        IntentState::Reserved => "Reserved",
        IntentState::Dispatching => "Dispatching",
        IntentState::Completed => "Completed",
        IntentState::Failed => "Failed",
        IntentState::Invalidated => "Invalidated",
        IntentState::Abandoned => "Abandoned",
    }
}

#[cfg(test)]
mod tests {
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
                "gocode-{name}-schema-{}-{nonce}.sqlite",
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
}
