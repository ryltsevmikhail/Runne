use crate::verification::digest::VerificationDigest;
use crate::verification::identity::*;

#[derive(Clone, Debug)]
pub struct BackupManifestRef {
    pub backup_id: BackupID,
    pub runtime_version: String,
    pub schema_version: u32,
    pub streams: Vec<StreamInventory>,
    pub blob_inventory_digest: VerificationDigest,
    pub archive_file_digest: VerificationDigest,
    pub lease_ref: String,
    pub integrity_result: bool,
    pub high_water_mark: u64,
    pub integrity_digest: VerificationDigest,
}

#[derive(Clone, Debug)]
pub struct StreamInventory {
    pub stream_name: String,
    pub event_count: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
}

#[derive(Clone, Debug)]
pub struct RetentionPolicy {
    pub retention_days: u32,
    pub keep_last_n_runs_per_plan: u32,
    pub keep_failed_runs_days: u32,
    pub prune_batch_size: u32,
}

impl RetentionPolicy {
    pub fn new(
        retention_days: u32,
        keep_last_n: u32,
        keep_failed: u32,
        batch: u32,
    ) -> Result<Self, String> {
        if retention_days == 0 {
            return Err("retention_days must be > 0".into());
        }
        Ok(Self {
            retention_days,
            keep_last_n_runs_per_plan: keep_last_n,
            keep_failed_runs_days: keep_failed,
            prune_batch_size: batch,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PruningEntry {
    pub run_id: RunID,
    pub reason: String,
    pub pruned_at: String,
    pub blob_count: u64,
}

#[derive(Clone, Debug)]
pub struct ExportRunJson {
    pub run_id: RunID,
    pub plan_id: PlanID,
    pub state: String,
    pub result: Option<String>,
    pub evidence_count: u32,
    pub contract_version: String,
    pub schema_digest: VerificationDigest,
    pub integrity_digest: VerificationDigest,
}

#[derive(Clone, Debug)]
pub struct PromotionPolicy {
    pub plan_eval_digest: VerificationDigest,
    pub target_artifact_digest: VerificationDigest,
    pub target_configuration_digest: VerificationDigest,
    pub auto_promote: bool,
    pub max_staleness_days: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_policy_valid() {
        assert!(RetentionPolicy::new(30, 5, 90, 100).is_ok());
    }
    #[test]
    fn retention_policy_zero_rejected() {
        assert!(RetentionPolicy::new(0, 5, 90, 100).is_err());
    }
    #[test]
    fn backup_manifest_has_required_fields() {
        let m = BackupManifestRef {
            backup_id: uuid::Uuid::now_v7(),
            runtime_version: "1.0".into(),
            schema_version: 1,
            streams: vec![],
            blob_inventory_digest: VerificationDigest::from_bytes([0; 32]),
            archive_file_digest: VerificationDigest::from_bytes([0; 32]),
            lease_ref: "lease1".into(),
            integrity_result: true,
            high_water_mark: 100,
            integrity_digest: VerificationDigest::from_bytes([0; 32]),
        };
        assert!(m.integrity_result);
    }
    #[test]
    fn export_dto_has_version_fields() {
        let e = ExportRunJson {
            run_id: uuid::Uuid::now_v7(),
            plan_id: uuid::Uuid::now_v7(),
            state: "completed".into(),
            result: Some("passed".into()),
            evidence_count: 5,
            contract_version: "1.0".into(),
            schema_digest: VerificationDigest::from_bytes([1; 32]),
            integrity_digest: VerificationDigest::from_bytes([2; 32]),
        };
        assert_eq!(e.contract_version, "1.0");
    }
}
