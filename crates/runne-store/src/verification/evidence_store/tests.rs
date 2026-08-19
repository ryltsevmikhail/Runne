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
            "runne-evidence-reopen-{}-{nonce}.sqlite",
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
