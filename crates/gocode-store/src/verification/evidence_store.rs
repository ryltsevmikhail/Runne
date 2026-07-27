use async_trait::async_trait;
use gocode_application::verification::evidence_recorder::*;
use gocode_domain::verification::digest::{DigestContract, VerificationDigest};
use gocode_domain::verification::evidence::*;
use gocode_domain::verification::identity::*;
use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory evidence store implementation.
pub struct InMemoryEvidenceStore {
    items: Mutex<HashMap<EvidenceRefID, EvidenceItem>>,
}

impl InMemoryEvidenceStore {
    pub fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
        }
    }
}

// Simple secret pattern scanner
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

#[async_trait]
impl EvidenceRecorder for InMemoryEvidenceStore {
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

        let item = EvidenceItem {
            evidence_ref_id: ref_id,
            run_id,
            profile_id,
            profile_digest,
            layer,
            evidence_type,
            evidence_digest,
            content_ref: format!("blob:{}", ref_id),
            source: "store".into(),
            producer_identity: producer_identity.to_string(),
            sensitivity,
            verified_by: "in-memory".into(),
        };

        let mut items = self.items.lock().unwrap();
        items.insert(ref_id, item);
        Ok(ref_id)
    }

    async fn validate(&self, ref_id: &EvidenceRefID) -> Result<(), EvidenceRecorderError> {
        let items = self.items.lock().unwrap();
        items.get(ref_id).ok_or(EvidenceRecorderError::NotFound)?;
        Ok(())
    }

    async fn get(&self, ref_id: &EvidenceRefID) -> Result<EvidenceItem, EvidenceRecorderError> {
        let items = self.items.lock().unwrap();
        items
            .get(ref_id)
            .cloned()
            .ok_or(EvidenceRecorderError::NotFound)
    }

    async fn list_for_run(
        &self,
        run_id: &RunID,
    ) -> Result<Vec<EvidenceRefID>, EvidenceRecorderError> {
        let items = self.items.lock().unwrap();
        Ok(items
            .values()
            .filter(|i| &i.run_id == run_id)
            .map(|i| i.evidence_ref_id)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn record_clean_content() {
        let store = InMemoryEvidenceStore::new();
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
        let store = InMemoryEvidenceStore::new();
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
        let store = InMemoryEvidenceStore::new();
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
        let store = InMemoryEvidenceStore::new();
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
}
