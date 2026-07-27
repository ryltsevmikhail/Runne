use gocode_application::verification::evidence_recorder::EvidenceRecorder;
use gocode_domain::verification::digest::VerificationDigest;
use gocode_domain::verification::evidence::{EvidenceLayer, EvidenceType, SensitivityLabel};
use gocode_store::verification::evidence_store::InMemoryEvidenceStore;
use uuid::Uuid;

#[tokio::test]
async fn secret_content_rejected_before_persistence() {
    let store = InMemoryEvidenceStore::new();
    let d = VerificationDigest::from_bytes([1; 32]);
    let rid = Uuid::now_v7();
    let pid = Uuid::now_v7();

    // Secret in content → rejected BEFORE store
    let result = store
        .record_raw(
            rid,
            pid,
            d.clone(),
            EvidenceLayer::L0,
            EvidenceType::TestResult,
            b"api_key: sk-abcdef",
            "producer",
            SensitivityLabel::Public,
        )
        .await;
    assert!(result.is_err());

    // Verify no evidence was stored
    let list = store.list_for_run(&rid).await.unwrap();
    assert!(list.is_empty());
}

#[tokio::test]
async fn private_key_content_rejected() {
    let store = InMemoryEvidenceStore::new();
    let d = VerificationDigest::from_bytes([1; 32]);
    let result = store
        .record_raw(
            Uuid::now_v7(),
            Uuid::now_v7(),
            d,
            EvidenceLayer::L0,
            EvidenceType::TestResult,
            b"-----BEGIN RSA PRIVATE KEY-----",
            "producer",
            SensitivityLabel::Public,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn cross_profile_evidence_isolation() {
    let store = InMemoryEvidenceStore::new();
    let d1 = VerificationDigest::from_bytes([1; 32]);
    let d2 = VerificationDigest::from_bytes([2; 32]);

    let rid1 = Uuid::now_v7();
    let rid2 = Uuid::now_v7();

    store
        .record_raw(
            rid1,
            Uuid::now_v7(),
            d1,
            EvidenceLayer::L0,
            EvidenceType::TestResult,
            b"test1",
            "p",
            SensitivityLabel::Public,
        )
        .await
        .unwrap();
    store
        .record_raw(
            rid2,
            Uuid::now_v7(),
            d2,
            EvidenceLayer::L0,
            EvidenceType::TestResult,
            b"test2",
            "p",
            SensitivityLabel::Public,
        )
        .await
        .unwrap();

    let list1 = store.list_for_run(&rid1).await.unwrap();
    let list2 = store.list_for_run(&rid2).await.unwrap();
    assert_eq!(list1.len(), 1);
    assert_eq!(list2.len(), 1);
    assert_ne!(list1[0], list2[0]);
}
