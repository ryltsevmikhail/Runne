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
        let contract = DigestContract::new("runne:evidence-content:v1");
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
