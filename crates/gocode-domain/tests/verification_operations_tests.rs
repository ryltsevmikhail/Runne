use gocode_domain::verification::backup::*;
use gocode_domain::verification::digest::VerificationDigest;
use uuid::Uuid;

#[test]
fn retention_policy_rejects_zero() {
    assert!(RetentionPolicy::new(0, 5, 90, 10).is_err());
    assert!(RetentionPolicy::new(30, 5, 90, 10).is_ok());
}

#[test]
fn backup_manifest_integrity_flag() {
    let m = BackupManifestRef {
        backup_id: Uuid::now_v7(), runtime_version: "1.0".into(), schema_version: 1,
        streams: vec![], blob_inventory_digest: VerificationDigest::from_bytes([0;32]),
        archive_file_digest: VerificationDigest::from_bytes([1;32]),
        lease_ref: "lease-1".into(), integrity_result: true, high_water_mark: 42,
        integrity_digest: VerificationDigest::from_bytes([2;32]),
    };
    assert!(m.integrity_result);
    assert_eq!(m.high_water_mark, 42);
}

#[test]
fn export_dto_contract_version_present() {
    let e = ExportRunJson {
        run_id: Uuid::now_v7(), plan_id: Uuid::now_v7(),
        state: "completed".into(), result: Some("passed".into()),
        evidence_count: 3, contract_version: "1.0".into(),
        schema_digest: VerificationDigest::from_bytes([1;32]),
        integrity_digest: VerificationDigest::from_bytes([2;32]),
    };
    assert!(!e.contract_version.is_empty());
    assert!(!e.schema_digest.as_bytes().iter().all(|b| *b == 0));
}

#[test]
fn promotion_policy_auto_promote() {
    let p = PromotionPolicy {
        plan_eval_digest: VerificationDigest::from_bytes([1;32]),
        target_artifact_digest: VerificationDigest::from_bytes([2;32]),
        target_configuration_digest: VerificationDigest::from_bytes([3;32]),
        auto_promote: true, max_staleness_days: 7,
    };
    assert!(p.auto_promote);
}
