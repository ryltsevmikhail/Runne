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
