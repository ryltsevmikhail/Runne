use runne_application::verification::evidence_recorder::EvidenceRecorder;

use super::*;

#[tokio::test]
async fn source_pinned_writer_digest_is_metadata_only_and_rejects_runne_alias() {
    let store = SqliteEvidenceStore::open_in_memory().unwrap();
    let evidence_id = store
        .record_raw(
            uuid::Uuid::from_bytes([1; 16]),
            uuid::Uuid::from_bytes([2; 16]),
            VerificationDigest::from_bytes([3; 32]),
            EvidenceLayer::L0,
            EvidenceType::TestResult,
            b"sourcecraft-evidence-v1",
            "sourcecraft",
            SensitivityLabel::Public,
        )
        .await
        .unwrap();
    let item = store.get(&evidence_id).await.unwrap();
    let canonical = VerificationDigest::from_hex(
        "33e09db2ebca78ac61177e7f930984a2fd3a5ed06c3a7e9644a2560d7253b142",
    )
    .unwrap();
    let runne_alias = VerificationDigest::from_hex(
        "5cd795b28aadfbada11fb5626adf0d9ae39ca63839bfd30a3d6c006b35aa9934",
    )
    .unwrap();
    assert_eq!(item.evidence_digest, canonical);
    assert_ne!(item.evidence_digest, runne_alias);
    assert_eq!(item.content_ref, format!("blob:{evidence_id}"));
    store.validate(&evidence_id).await.unwrap();

    let connection = store.conn.lock().unwrap();
    let columns = connection
        .prepare("SELECT name FROM pragma_table_info('verification_evidence') ORDER BY cid")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!columns.iter().any(|column| column == "raw_content"));
    assert!(
        !columns
            .iter()
            .any(|column| column == "content_read_authorization")
    );
    let content_tables: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'verification_evidence_content'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(content_tables, 0);
}
