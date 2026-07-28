use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use gocode_application::verification::evidence_recorder::*;
use gocode_domain::verification::digest::{DigestContract, VerificationDigest};
use gocode_domain::verification::evidence::*;
use gocode_domain::verification::identity::*;
use rusqlite::{Connection, TransactionBehavior, params};

use crate::schema;

/// SQLite-backed evidence store.
///
/// Writes are serialized through a single connection behind `spawn_blocking`.
/// Every atomic write uses `BEGIN IMMEDIATE` for CAS semantics.
#[derive(Clone)]
pub struct SqliteEvidenceStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteEvidenceStore {
    /// Open a durable evidence store using the canonical schema migrations.
    pub fn open(db_path: &Path) -> Result<Self, rusqlite::Error> {
        schema::preflight_existing_file(db_path)?;
        let conn = schema::open_with_pragmas(&db_path.to_string_lossy())?;
        schema::apply_migrations(&conn)?;
        schema::run_startup_gates(&conn, &db_path.to_string_lossy())?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory evidence store using the canonical schema migrations.
    #[doc(hidden)]
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        schema::apply_migrations(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

// ── Enum ↔ integer conversion ──────────────────────────────────────────────

fn layer_to_int(layer: &EvidenceLayer) -> i64 {
    match layer {
        EvidenceLayer::L0 => 0,
        EvidenceLayer::L1 => 1,
        EvidenceLayer::L2S => 2,
        EvidenceLayer::L2I => 3,
        EvidenceLayer::L3 => 4,
        EvidenceLayer::L4 => 5,
    }
}

fn layer_from_int(v: i64) -> Result<EvidenceLayer, EvidenceRecorderError> {
    match v {
        0 => Ok(EvidenceLayer::L0),
        1 => Ok(EvidenceLayer::L1),
        2 => Ok(EvidenceLayer::L2S),
        3 => Ok(EvidenceLayer::L2I),
        4 => Ok(EvidenceLayer::L3),
        5 => Ok(EvidenceLayer::L4),
        _ => Err(EvidenceRecorderError::CorruptData),
    }
}

fn evidence_type_to_int(et: &EvidenceType) -> i64 {
    match et {
        EvidenceType::TestResult => 0,
        EvidenceType::SemanticTrace => 1,
        EvidenceType::HumanReview => 2,
        EvidenceType::Metric => 3,
        EvidenceType::AuditRecord => 4,
    }
}

fn evidence_type_from_int(v: i64) -> Result<EvidenceType, EvidenceRecorderError> {
    match v {
        0 => Ok(EvidenceType::TestResult),
        1 => Ok(EvidenceType::SemanticTrace),
        2 => Ok(EvidenceType::HumanReview),
        3 => Ok(EvidenceType::Metric),
        4 => Ok(EvidenceType::AuditRecord),
        _ => Err(EvidenceRecorderError::CorruptData),
    }
}

fn sensitivity_to_int(s: &SensitivityLabel) -> i64 {
    match s {
        SensitivityLabel::Public => 0,
        SensitivityLabel::Internal => 1,
        SensitivityLabel::Sensitive => 2,
    }
}

fn sensitivity_from_int(v: i64) -> Result<SensitivityLabel, EvidenceRecorderError> {
    match v {
        0 => Ok(SensitivityLabel::Public),
        1 => Ok(SensitivityLabel::Internal),
        2 => Ok(SensitivityLabel::Sensitive),
        _ => Err(EvidenceRecorderError::CorruptData),
    }
}

// ── Row mapping ─────────────────────────────────────────────────────────────

fn read_evidence_row(row: &rusqlite::Row) -> rusqlite::Result<EvidenceItem> {
    let evidence_id_blob: Vec<u8> = row.get(0)?;
    let run_id_blob: Vec<u8> = row.get(1)?;
    let profile_id_blob: Vec<u8> = row.get(2)?;
    let profile_digest_blob: Vec<u8> = row.get(3)?;
    let layer_int: i64 = row.get(4)?;
    let evidence_type_int: i64 = row.get(5)?;
    let evidence_digest_blob: Vec<u8> = row.get(6)?;
    let content_ref: String = row.get(7)?;
    let source: String = row.get(8)?;
    let producer_identity: String = row.get(9)?;
    let sensitivity_int: i64 = row.get(10)?;
    let verified_by: String = row.get(11)?;

    let evidence_ref_id = blob_to_uuid(&evidence_id_blob, 0)?;
    let run_id = blob_to_uuid(&run_id_blob, 1)?;
    let profile_id = blob_to_uuid(&profile_id_blob, 2)?;
    let profile_digest = VerificationDigest::from_bytes(blob_to_digest(&profile_digest_blob, 3)?);
    let evidence_digest = VerificationDigest::from_bytes(blob_to_digest(&evidence_digest_blob, 6)?);

    let layer = layer_from_int(layer_int).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad layer",
            )),
        )
    })?;
    let evidence_type = evidence_type_from_int(evidence_type_int).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad evidence_type",
            )),
        )
    })?;
    let sensitivity = sensitivity_from_int(sensitivity_int).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            10,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad sensitivity",
            )),
        )
    })?;

    Ok(EvidenceItem {
        evidence_ref_id,
        run_id,
        profile_id,
        profile_digest,
        layer,
        evidence_type,
        evidence_digest,
        content_ref,
        source,
        producer_identity,
        sensitivity,
        verified_by,
    })
}

fn blob_to_uuid(bytes: &[u8], index: usize) -> rusqlite::Result<uuid::Uuid> {
    let array: [u8; 16] = bytes
        .try_into()
        .map_err(|_| corrupt_column(index, "UUID"))?;
    Ok(uuid::Uuid::from_bytes(array))
}

fn blob_to_digest(bytes: &[u8], index: usize) -> rusqlite::Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| corrupt_column(index, "digest"))
}

fn corrupt_column(index: usize, field: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid {field}"),
        )),
    )
}

fn map_query_error(error: rusqlite::Error) -> EvidenceRecorderError {
    match error {
        rusqlite::Error::QueryReturnedNoRows => EvidenceRecorderError::NotFound,
        _ => EvidenceRecorderError::CorruptData,
    }
}

// ── Secret scanner ──────────────────────────────────────────────────────────

fn scan_for_secrets(content: &[u8]) -> Result<(), EvidenceRecorderError> {
    let s = String::from_utf8_lossy(content);
    if s.contains("sk-")
        || s.contains("api_key")
        || s.contains("private_key")
        || s.contains("BEGIN RSA PRIVATE KEY")
    {
        return Err(EvidenceRecorderError::SecretContentDetected);
    }
    Ok(())
}

// ── EvidenceRecorder impl ───────────────────────────────────────────────────

#[async_trait]
impl EvidenceRecorder for SqliteEvidenceStore {
    async fn record_raw(
        &self,
        run_id: RunID,
        profile_id: ProfileID,
        profile_digest: VerificationDigest,
        layer: EvidenceLayer,
        evidence_type: EvidenceType,
        raw_content: &[u8],
        producer_identity: &str,
        sensitivity: SensitivityLabel,
    ) -> Result<EvidenceRefID, EvidenceRecorderError> {
        // Scan BEFORE any persistence
        scan_for_secrets(raw_content)?;

        // Compute digest
        let contract = DigestContract::new("gocode:evidence-content:v1");
        let evidence_digest = contract.compute(&[raw_content]);
        let ref_id = uuid::Uuid::now_v7();

        let content_ref = format!("blob:{}", ref_id);
        let source = "store".to_string();
        let verified_by = "sqlite".to_string();
        let producer_identity = producer_identity.to_string();

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = conn
                .lock()
                .map_err(|_| EvidenceRecorderError::CorruptData)?;

            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| EvidenceRecorderError::CorruptData)?;

            // Check for duplicate evidence_id
            let exists: bool = tx
                .query_row(
                    "SELECT COUNT(*) FROM verification_evidence WHERE evidence_id = ?1",
                    params![ref_id.as_bytes()],
                    |row| row.get::<_, i64>(0),
                )
                .map(|c| c > 0)
                .map_err(map_query_error)?;

            if exists {
                return Err(EvidenceRecorderError::AlreadyRecorded);
            }

            tx.execute(
                "INSERT INTO verification_evidence
                 (evidence_id, run_id, profile_id, profile_digest,
                  layer, evidence_type, evidence_digest, content_ref,
                  source, producer_identity, sensitivity, verified_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    ref_id.as_bytes(),
                    run_id.as_bytes(),
                    profile_id.as_bytes(),
                    profile_digest.as_bytes(),
                    layer_to_int(&layer),
                    evidence_type_to_int(&evidence_type),
                    evidence_digest.as_bytes(),
                    content_ref,
                    source,
                    producer_identity,
                    sensitivity_to_int(&sensitivity),
                    verified_by,
                ],
            )
            .map_err(|_| EvidenceRecorderError::CorruptData)?;

            tx.commit()
                .map_err(|_| EvidenceRecorderError::CorruptData)?;
            Ok(ref_id)
        })
        .await
        .map_err(|_| EvidenceRecorderError::CorruptData)?
    }

    async fn validate(&self, ref_id: &EvidenceRefID) -> Result<(), EvidenceRecorderError> {
        let conn = self.conn.clone();
        let rid = *ref_id;
        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|_| EvidenceRecorderError::CorruptData)?;
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM verification_evidence WHERE evidence_id = ?1",
                    params![rid.as_bytes()],
                    |row| row.get(0),
                )
                .map_err(map_query_error)?;
            if count == 0 {
                return Err(EvidenceRecorderError::NotFound);
            }
            Ok(())
        })
        .await
        .map_err(|_| EvidenceRecorderError::CorruptData)?
    }

    async fn get(&self, ref_id: &EvidenceRefID) -> Result<EvidenceItem, EvidenceRecorderError> {
        let conn = self.conn.clone();
        let rid = *ref_id;
        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|_| EvidenceRecorderError::CorruptData)?;
            conn.query_row(
                "SELECT evidence_id, run_id, profile_id, profile_digest,
                        layer, evidence_type, evidence_digest, content_ref,
                        source, producer_identity, sensitivity, verified_by
                 FROM verification_evidence
                 WHERE evidence_id = ?1",
                params![rid.as_bytes()],
                read_evidence_row,
            )
            .map_err(map_query_error)
        })
        .await
        .map_err(|_| EvidenceRecorderError::CorruptData)?
    }

    async fn list_for_run(
        &self,
        run_id: &RunID,
    ) -> Result<Vec<EvidenceRefID>, EvidenceRecorderError> {
        let conn = self.conn.clone();
        let rid = *run_id;
        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|_| EvidenceRecorderError::CorruptData)?;
            let mut stmt = conn
                .prepare("SELECT evidence_id FROM verification_evidence WHERE run_id = ?1")
                .map_err(map_query_error)?;

            let rows = stmt
                .query_map(params![rid.as_bytes()], |row| row.get::<_, Vec<u8>>(0))
                .map_err(map_query_error)?;

            let mut ids = Vec::new();
            for row in rows {
                let blob = row.map_err(map_query_error)?;
                ids.push(blob_to_uuid(&blob, 0).map_err(map_query_error)?);
            }
            Ok(ids)
        })
        .await
        .map_err(|_| EvidenceRecorderError::CorruptData)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use uuid::Uuid;

    #[tokio::test]
    async fn record_clean_content() {
        let store = SqliteEvidenceStore::open_in_memory().unwrap();
        let d = VerificationDigest::from_bytes([1; 32]);
        let r = store
            .record_raw(
                Uuid::now_v7(),
                Uuid::now_v7(),
                d,
                EvidenceLayer::L0,
                EvidenceType::TestResult,
                b"test",
                "producer",
                SensitivityLabel::Public,
            )
            .await
            .unwrap();
        let item = store.get(&r).await.unwrap();
        assert_eq!(item.evidence_type, EvidenceType::TestResult);
    }

    #[tokio::test]
    async fn record_rejects_secrets() {
        let store = SqliteEvidenceStore::open_in_memory().unwrap();
        let d = VerificationDigest::from_bytes([1; 32]);
        let r = store
            .record_raw(
                Uuid::now_v7(),
                Uuid::now_v7(),
                d,
                EvidenceLayer::L0,
                EvidenceType::TestResult,
                b"api_key: sk-12345",
                "producer",
                SensitivityLabel::Public,
            )
            .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn evidence_immutable() {
        let store = SqliteEvidenceStore::open_in_memory().unwrap();
        let d = VerificationDigest::from_bytes([1; 32]);
        let r1 = store
            .record_raw(
                Uuid::now_v7(),
                Uuid::now_v7(),
                d.clone(),
                EvidenceLayer::L0,
                EvidenceType::TestResult,
                b"test1",
                "producer",
                SensitivityLabel::Public,
            )
            .await
            .unwrap();
        let r2 = store
            .record_raw(
                Uuid::now_v7(),
                Uuid::now_v7(),
                d,
                EvidenceLayer::L0,
                EvidenceType::TestResult,
                b"test2",
                "producer",
                SensitivityLabel::Public,
            )
            .await
            .unwrap();
        assert_ne!(r1, r2);
        let i1 = store.get(&r1).await.unwrap();
        assert_eq!(i1.content_ref, format!("blob:{}", r1));
    }

    #[tokio::test]
    async fn list_for_run_filters_correctly() {
        let store = SqliteEvidenceStore::open_in_memory().unwrap();
        let d = VerificationDigest::from_bytes([1; 32]);
        let rid = Uuid::now_v7();
        store
            .record_raw(
                rid,
                Uuid::now_v7(),
                d.clone(),
                EvidenceLayer::L0,
                EvidenceType::TestResult,
                b"a",
                "p",
                SensitivityLabel::Public,
            )
            .await
            .unwrap();
        store
            .record_raw(
                Uuid::now_v7(),
                Uuid::now_v7(),
                d,
                EvidenceLayer::L0,
                EvidenceType::TestResult,
                b"b",
                "p",
                SensitivityLabel::Public,
            )
            .await
            .unwrap();
        let list = store.list_for_run(&rid).await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn duplicate_evidence_id_rejected() {
        let store = SqliteEvidenceStore::open_in_memory().unwrap();
        let d = VerificationDigest::from_bytes([1; 32]);
        let rid = Uuid::now_v7();
        let pid = Uuid::now_v7();

        // Record once
        store
            .record_raw(
                rid,
                pid,
                d.clone(),
                EvidenceLayer::L0,
                EvidenceType::TestResult,
                b"test",
                "producer",
                SensitivityLabel::Public,
            )
            .await
            .unwrap();

        // Secret content rejected BEFORE any store check
        let secret_result = store
            .record_raw(
                Uuid::now_v7(),
                Uuid::now_v7(),
                d,
                EvidenceLayer::L0,
                EvidenceType::TestResult,
                b"api_key: sk-12345",
                "producer",
                SensitivityLabel::Public,
            )
            .await;
        assert!(secret_result.is_err());
    }

    #[tokio::test]
    async fn get_rejects_a_corrupted_digest_without_reporting_not_found() {
        let store = SqliteEvidenceStore::open_in_memory().unwrap();
        let evidence_id = store
            .record_raw(
                Uuid::now_v7(),
                Uuid::now_v7(),
                VerificationDigest::from_bytes([1; 32]),
                EvidenceLayer::L0,
                EvidenceType::TestResult,
                b"clean",
                "producer",
                SensitivityLabel::Public,
            )
            .await
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            conn.execute(
                "UPDATE verification_evidence SET evidence_digest = zeroblob(31) WHERE evidence_id = ?1",
                params![evidence_id.as_bytes()],
            )
            .unwrap();
            conn.execute_batch("PRAGMA ignore_check_constraints = OFF;")
                .unwrap();
        }

        let result = store.get(&evidence_id).await;
        assert!(matches!(result, Err(EvidenceRecorderError::CorruptData)));
    }

    #[test]
    fn duplicate_evidence_id_fails_without_mutating_existing_row() {
        let store = SqliteEvidenceStore::open_in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        let evidence_id = [1_u8; 16];
        let row = params![
            evidence_id.as_slice(),
            [2_u8; 16].as_slice(),
            [3_u8; 16].as_slice(),
            [4_u8; 32].as_slice(),
            [5_u8; 32].as_slice(),
        ];
        conn.execute(
            "INSERT INTO verification_evidence
             (evidence_id, run_id, profile_id, profile_digest, layer, evidence_type,
              evidence_digest, content_ref, source, producer_identity, sensitivity, verified_by)
             VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, 'blob:one', 'store', 'producer', 0, 'sqlite')",
            row,
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO verification_evidence
                 (evidence_id, run_id, profile_id, profile_digest, layer, evidence_type,
                  evidence_digest, content_ref, source, producer_identity, sensitivity, verified_by)
                 VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, 'blob:two', 'store', 'producer', 0, 'sqlite')",
                params![
                    evidence_id.as_slice(),
                    [6_u8; 16].as_slice(),
                    [7_u8; 16].as_slice(),
                    [8_u8; 32].as_slice(),
                    [9_u8; 32].as_slice(),
                ],
            )
            .is_err()
        );
        let content_ref: String = conn
            .query_row(
                "SELECT content_ref FROM verification_evidence WHERE evidence_id = ?1",
                params![evidence_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(content_ref, "blob:one");
    }

    #[tokio::test]
    async fn durable_open_uses_canonical_schema_and_persists_evidence_after_reopen() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gocode-evidence-reopen-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let store = SqliteEvidenceStore::open(&path).unwrap();
        let evidence_id = store
            .record_raw(
                Uuid::now_v7(),
                Uuid::now_v7(),
                VerificationDigest::from_bytes([1; 32]),
                EvidenceLayer::L1,
                EvidenceType::Metric,
                b"clean",
                "producer",
                SensitivityLabel::Internal,
            )
            .await
            .unwrap();
        drop(store);

        let reopened = SqliteEvidenceStore::open(&path).unwrap();
        assert_eq!(
            reopened.get(&evidence_id).await.unwrap().evidence_ref_id,
            evidence_id
        );
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
