use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000001";
pub const COMMAND: &str = "018f2e3a-7000-7000-8000-000000000002";

fn args(values: &[&str]) -> VecDeque<OsString> {
    values.iter().map(OsString::from).collect()
}

pub struct MemoryIndex {
    pub records: Mutex<Vec<(String, String, Vec<u8>)>>,
    pub fail_create: AtomicBool,
    pub events: Arc<Mutex<Vec<&'static str>>>,
}

impl Default for MemoryIndex {
    fn default() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            fail_create: AtomicBool::new(false),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl PermissionRecoveryIndex for MemoryIndex {
    fn read_existing(
        &self,
        _scope: &str,
        command_id: CanonicalId,
    ) -> Result<Option<Vec<u8>>, RecoveryError> {
        let records = self.records.lock().unwrap();
        let mut found = records
            .iter()
            .filter(|(_, id, _)| id == &command_id.to_string());
        let record = found.next().map(|(_, _, bytes)| bytes.clone());
        if found.next().is_some() {
            return Err(RecoveryError::Corrupt);
        }
        drop(records);
        Ok(record)
    }

    fn create_exclusive(
        &self,
        scope: &str,
        command_id: CanonicalId,
        record: &[u8],
    ) -> Result<RecordCreateResult, RecoveryError> {
        if self.fail_create.load(Ordering::Relaxed) {
            return Err(RecoveryError::Io);
        }
        let mut records = self.records.lock().unwrap();
        if let Some((_, _, bytes)) = records
            .iter()
            .find(|(_, id, _)| id == &command_id.to_string())
        {
            return Ok(RecordCreateResult::Existing(bytes.clone()));
        }
        records.push((scope.to_owned(), command_id.to_string(), record.to_vec()));
        drop(records);
        self.events.lock().unwrap().push("record_durable");
        Ok(RecordCreateResult::DurableCreated)
    }
}

pub fn intent() -> PermissionModeSetIntent {
    PermissionModeSetIntent {
        workspace_id: CanonicalId::parse(WORKSPACE).unwrap(),
        command_id: CanonicalId::parse(COMMAND).unwrap(),
        idempotency_key: "cli-key-01".to_owned(),
        requested_mode: runne_runtime_client::PermissionModeV1::FullAccess,
        expected_authorization_revision: 9,
        preset_version: 1,
        expires_at_unix_ms: None,
    }
}

pub fn session_info() -> runne_runtime_client::RuntimeSessionInfo {
    runne_runtime_client::RuntimeSessionInfo {
        profile_id: "profile-test".to_owned(),
        schema_hash: "11".repeat(32),
        runtime_version: "1.0.0".to_owned(),
        capabilities: vec!["project.list.v1".to_owned()],
        authority_id: "018f2e3a700070008000000000000003".to_owned(),
        principal_id: "principal:test-user".to_owned(),
        event_log_lineage_id: "018f2e3a-7000-7000-8000-000000000004".to_owned(),
        daemon_instance_id: "018f2e3a-7000-7000-8000-000000000005".to_owned(),
        launch_generation: 1,
        session_id: "22".repeat(16),
        authorization_epoch: 1,
        sensitivity_ceiling: "secret".to_owned(),
        certificate_sha256: "33".repeat(32),
        capability_digest: "856c42176e1143c9c9db2d3301ee16b2307db4f36b2e9551fe0b6e2e4d3fa4e4"
            .to_owned(),
    }
}

pub fn current_status() -> PermissionModeStatusV1 {
    PermissionModeStatusV1 {
        selected_mode: runne_runtime_client::PermissionModeV1::AskAlways,
        effective: runne_runtime_client::PermissionEffectiveStateV1::NotReady {
            reason: runne_runtime_client::PermissionModeNotReadyReasonV1::PresetUnavailable,
        },
        authorization_revision: 9,
        preset_version: runne_runtime_client::PermissionPresetVersionV1::V1,
        managed_policy_version: 1,
        pending_approval_ids: Vec::new(),
        containment: None,
        network_state: runne_runtime_client::PermissionNetworkStateV1::Unavailable,
        expires_at_unix_ms: None,
    }
}

pub fn pending(command_id: CanonicalId) -> PermissionModeCommandStatusV2 {
    serde_json::from_value(serde_json::json!({
        "state": "pending_native_confirmation",
        "commandId": canonical_id_bytes(command_id).unwrap(),
        "expiresAtUnixMs": 1_800_000_000_000_i64
    }))
    .expect("strict pending command fixture")
}

pub fn saved_record(intent: &PermissionModeSetIntent) -> Vec<u8> {
    make_recovery_record(
        intent,
        StableRuntimeIdentity::from_session(&session_info()).unwrap(),
        RuntimeAuditSnapshot::from_session(&session_info()).unwrap(),
    )
    .unwrap()
}

#[path = "tests/command_tests.rs"]
mod command_tests;
