use super::*;
use crate::permissions_tests::{current_status, intent, pending, session_info};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000001";
const COMMAND: &str = "018f2e3a-7000-7000-8000-000000000002";

struct FakePermissionRuntime {
    status: runne_runtime_client::PermissionModeStatusV1,
    command_status: runne_runtime_client::PermissionModeCommandStatusV2,
    approvals: Vec<runne_runtime_client::ApprovalSummaryDto>,
    calls: RefCell<Vec<&'static str>>,
}

impl PermissionsRuntime for FakePermissionRuntime {
    fn permission_mode_status(
        &self,
        _workspace_id: CanonicalId,
    ) -> PermissionFuture<'_, runne_runtime_client::PermissionModeStatusV1> {
        self.calls.borrow_mut().push("status");
        let result = self.status.clone();
        Box::pin(async move { Ok(result) })
    }

    fn permission_mode_command_status(
        &self,
        _workspace_id: CanonicalId,
        _command_id: CanonicalId,
    ) -> PermissionFuture<'_, runne_runtime_client::PermissionModeCommandStatusV2> {
        self.calls.borrow_mut().push("command_status");
        let result = self.command_status.clone();
        Box::pin(async move { Ok(result) })
    }

    fn list_pending_approvals(
        &self,
    ) -> PermissionFuture<'_, Vec<runne_runtime_client::ApprovalSummaryDto>> {
        self.calls.borrow_mut().push("approvals");
        let result = self.approvals.clone();
        Box::pin(async move { Ok(result) })
    }
}

fn fixture() -> FakePermissionRuntime {
    let status = runne_runtime_client::PermissionModeStatusV1 {
        selected_mode: runne_runtime_client::PermissionModeV1::FullAccess,
        effective: runne_runtime_client::PermissionEffectiveStateV1::NotReady {
            reason: runne_runtime_client::PermissionModeNotReadyReasonV1::PresetUnavailable,
        },
        authorization_revision: 7,
        preset_version: runne_runtime_client::PermissionPresetVersionV1::V1,
        managed_policy_version: 3,
        pending_approval_ids: Vec::new(),
        containment: None,
        network_state: runne_runtime_client::PermissionNetworkStateV1::Unavailable,
        expires_at_unix_ms: None,
    };
    let command_status = serde_json::from_value(serde_json::json!({
        "state": "pending_native_confirmation",
        "commandId": canonical_id_bytes(CanonicalId::parse(COMMAND).unwrap()).unwrap(),
        "expiresAtUnixMs": 1_900_000_000_000_i64
    }))
    .expect("strict command status fixture");
    FakePermissionRuntime {
        status,
        command_status,
        approvals: Vec::new(),
        calls: RefCell::new(Vec::new()),
    }
}

pub struct RecoveryFakeRuntime {
    pub info: runne_runtime_client::RuntimeSessionInfo,
    pub command_id: CanonicalId,
    pub command: Mutex<runne_runtime_client::PermissionModeCommandStatusV2>,
    pub posts: AtomicUsize,
    pub status_gets: AtomicUsize,
    pub command_gets: AtomicUsize,
    pub unknown_after_post: AtomicBool,
    pub command_missing: AtomicBool,
    pub status_unavailable: AtomicBool,
    pub events: Arc<Mutex<Vec<&'static str>>>,
}

impl RecoveryFakeRuntime {
    pub fn new(command_id: CanonicalId, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            info: session_info(),
            command_id,
            command: Mutex::new(pending(command_id)),
            posts: AtomicUsize::new(0),
            status_gets: AtomicUsize::new(0),
            command_gets: AtomicUsize::new(0),
            unknown_after_post: AtomicBool::new(false),
            command_missing: AtomicBool::new(false),
            status_unavailable: AtomicBool::new(false),
            events,
        }
    }
}

impl PermissionsRuntime for RecoveryFakeRuntime {
    fn permission_mode_status(
        &self,
        _workspace_id: CanonicalId,
    ) -> PermissionFuture<'_, PermissionModeStatusV1> {
        Box::pin(async { Ok(current_status()) })
    }

    fn permission_mode_command_status(
        &self,
        _workspace_id: CanonicalId,
        _command_id: CanonicalId,
    ) -> PermissionFuture<'_, PermissionModeCommandStatusV2> {
        Box::pin(async move { Ok(self.command.lock().unwrap().clone()) })
    }

    fn list_pending_approvals(&self) -> PermissionFuture<'_, Vec<ApprovalSummaryDto>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl PermissionModeRuntime for RecoveryFakeRuntime {
    fn session_info(&self) -> &runne_runtime_client::RuntimeSessionInfo {
        &self.info
    }

    fn read_mode_status(
        &self,
        _workspace_id: CanonicalId,
    ) -> ModeFuture<'_, PermissionModeStatusV1> {
        Box::pin(async move {
            self.status_gets.fetch_add(1, Ordering::Relaxed);
            self.events.lock().unwrap().push("status_get");
            if self.status_unavailable.load(Ordering::Relaxed) {
                return Err(ModeApiError::Api(
                    CanonicalId::parse("invalid").unwrap_err(),
                ));
            }
            Ok(current_status())
        })
    }

    fn read_mode_command(
        &self,
        _workspace_id: CanonicalId,
        command_id: CanonicalId,
    ) -> ModeFuture<'_, PermissionModeCommandStatusV2> {
        Box::pin(async move {
            assert_eq!(command_id, self.command_id);
            self.command_gets.fetch_add(1, Ordering::Relaxed);
            self.events.lock().unwrap().push("command_get");
            if self.command_missing.load(Ordering::Relaxed) {
                return Err(ModeApiError::NotFound);
            }
            Ok(self.command.lock().unwrap().clone())
        })
    }

    fn request_permission_mode_change(
        &self,
        _request: runne_runtime_client::PermissionModeChangeRequestV1,
    ) -> ModeFuture<'_, PermissionModeCommandStatusV2> {
        Box::pin(async move {
            self.posts.fetch_add(1, Ordering::Relaxed);
            self.events.lock().unwrap().push("post");
            if self.unknown_after_post.load(Ordering::Relaxed) {
                return Err(ModeApiError::UnknownAfterSend);
            }
            Ok(self.command.lock().unwrap().clone())
        })
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_recovery_index_serializes_concurrent_creators() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let state_dir = std::env::current_dir()
        .unwrap()
        .join(format!(".cli-index-{}-{stamp}", std::process::id()));
    let input = intent();
    let info = session_info();
    let stable = StableRuntimeIdentity::from_session(&info).unwrap();
    let scope = scope_digest(&stable);
    let record = make_recovery_record(
        &input,
        stable,
        RuntimeAuditSnapshot::from_session(&info).unwrap(),
    )
    .unwrap();
    let id = input.command_id;
    let results = std::thread::scope(|threads| {
        let create = |path| {
            let index = LinuxPermissionRecoveryIndex::new(path);
            let scope = &scope;
            let record = &record;
            threads.spawn(move || index.create_exclusive(scope, id, record))
        };
        [create(state_dir.clone()), create(state_dir.clone())].map(|worker| worker.join().unwrap())
    });
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(RecordCreateResult::DurableCreated)))
            .count(),
        1
    );
    assert!(results.iter().all(|result| matches!(
        result,
        Ok(RecordCreateResult::DurableCreated | RecordCreateResult::Existing(_))
    )));
    std::fs::remove_dir_all(state_dir).unwrap();
}

#[test]
fn status_projects_selected_and_effective_independently_in_typed_json() {
    let runtime = fixture();
    let workspace_id = CanonicalId::parse(WORKSPACE).unwrap();
    let output = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_permissions(
            &runtime,
            PermissionsCommand::Status { workspace_id },
        ))
        .unwrap();
    let outcome = process_outcome(Ok(output.clone()), OutputFormat::Json);
    let envelope: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(envelope["data"]["selectedMode"], "full_access");
    assert_eq!(envelope["data"]["effective"]["state"], "notReady");
    assert_eq!(envelope["data"]["authorizationRevision"], 7);
    let text = output.render_text();
    assert!(text.contains("selected mode: Полный доступ"));
    assert!(text.contains("effective state: not ready"));
    assert_eq!(&*runtime.calls.borrow(), &["status"]);
}

#[test]
fn command_readback_reports_pending_native_action_without_claiming_commit() {
    let runtime = fixture();
    let workspace_id = CanonicalId::parse(WORKSPACE).unwrap();
    let command_id = CanonicalId::parse(COMMAND).unwrap();
    let command_id_json = serde_json::json!(canonical_id_bytes(command_id).unwrap());
    let output = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_permissions(
            &runtime,
            PermissionsCommand::CommandStatus {
                workspace_id,
                command_id,
            },
        ))
        .unwrap();
    let outcome = process_outcome(Ok(output.clone()), OutputFormat::Json);
    let envelope: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(envelope["data"]["state"], "pending_native_confirmation");
    assert_eq!(envelope["data"]["commandId"], command_id_json);
    assert_eq!(envelope["data"]["nativeActionRequired"], true);
    assert!(output.render_text().contains("native action: required"));
    assert_eq!(&*runtime.calls.borrow(), &["command_status"]);
}

#[test]
fn status_jsonl_is_one_typed_record_not_a_preformatted_json_string() {
    let runtime = fixture();
    let workspace_id = CanonicalId::parse(WORKSPACE).unwrap();
    let output = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_permissions(
            &runtime,
            PermissionsCommand::Status { workspace_id },
        ))
        .unwrap();
    let outcome = process_outcome(Ok(output), OutputFormat::Jsonl);
    let records: Vec<_> = outcome.stdout.lines().collect();
    assert_eq!(records.len(), 1);
    let record: serde_json::Value = serde_json::from_str(records[0]).unwrap();
    assert!(record["selectedMode"] == "full_access" && record["effective"]["state"] == "notReady");
}

#[test]
fn approval_list_is_a_separate_typed_empty_collection() {
    let runtime = fixture();
    let output = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_permissions(
            &runtime,
            PermissionsCommand::ApprovalsList,
        ))
        .unwrap();
    let outcome = process_outcome(Ok(output), OutputFormat::Json);
    let envelope: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(envelope["data"]["approvals"].as_array().unwrap().len(), 0);
    assert_eq!(&*runtime.calls.borrow(), &["approvals"]);
}
