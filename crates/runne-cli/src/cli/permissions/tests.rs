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

#[test]
fn parses_read_only_permission_commands_with_canonical_ids() {
    assert!(matches!(
        parse_permissions(args(&["status", "--workspace-id", WORKSPACE])),
        Ok(ParsedPermissionsCommand::Read(PermissionsCommand::Status { workspace_id }))
            if workspace_id.to_string() == WORKSPACE
    ));
    assert!(matches!(
        parse_permissions(args(&[
            "command", "status", "--workspace-id", WORKSPACE, "--command-id", COMMAND
        ])),
        Ok(ParsedPermissionsCommand::Read(PermissionsCommand::CommandStatus { workspace_id, command_id }))
            if workspace_id.to_string() == WORKSPACE && command_id.to_string() == COMMAND
    ));
    assert!(matches!(
        parse_permissions(args(&["approvals", "list"])),
        Ok(ParsedPermissionsCommand::Read(
            PermissionsCommand::ApprovalsList
        ))
    ));
}

#[test]
fn parses_explicit_approval_responses_and_rejects_automatic_confirmation_flags() {
    for (decision, expected) in [
        (
            "approve",
            runne_runtime_client::ApprovalDecisionDto::Approve,
        ),
        ("deny", runne_runtime_client::ApprovalDecisionDto::Deny),
    ] {
        assert!(matches!(
            parse_permissions(args(&[
                "approvals", "respond", "--approval-id", WORKSPACE, "--decision", decision,
                "--command-id", COMMAND, "--idempotency-key", "approval-key-01"
            ])),
            Ok(ParsedPermissionsCommand::ApprovalRespond(intent))
                if intent.approval_id.to_string() == WORKSPACE
                    && intent.command_id.to_string() == COMMAND
                    && intent.idempotency_key == "approval-key-01"
                    && intent.decision == expected
        ));
    }
    assert!(matches!(
        parse_permissions(args(&[
            "approvals",
            "respond",
            "--approval-id",
            WORKSPACE,
            "--decision",
            "approve",
            "--command-id",
            COMMAND,
            "--idempotency-key",
            "approval-key-01",
            "--yes"
        ])),
        Err(CliError::Usage)
    ));
}

#[test]
fn parses_explicit_mode_intent_without_generating_identity() {
    let result = parse_permissions(args(&[
        "mode",
        "set",
        "--workspace-id",
        WORKSPACE,
        "--command-id",
        COMMAND,
        "--idempotency-key",
        "cli-key-01",
        "--mode",
        "full_access",
        "--expected-revision",
        "9",
        "--preset-version",
        "1",
        "--expires-at-unix-ms",
        "none",
    ]));
    assert!(matches!(
        result,
        Ok(ParsedPermissionsCommand::ModeSet(intent))
            if intent.workspace_id.to_string() == WORKSPACE
                && intent.command_id.to_string() == COMMAND
                && intent.idempotency_key == "cli-key-01"
                && intent.requested_mode == runne_runtime_client::PermissionModeV1::FullAccess
                && intent.expected_authorization_revision == 9
                && intent.preset_version == 1
                && intent.expires_at_unix_ms.is_none()
    ));
}

#[test]
fn parser_rejects_ambiguous_or_unimplemented_commands() {
    let cases: &[&[&str]] = &[
        &["status"],
        &["status", "--workspace-id", "not-an-id"],
        &["status", "--workspace-id", WORKSPACE, "extra"],
        &["command", "status", "--workspace-id", WORKSPACE],
        &["approvals", "list", "extra"],
        &["mode", "set", "--workspace-id", WORKSPACE],
        &[
            "mode",
            "set",
            "--workspace-id",
            WORKSPACE,
            "--command-id",
            COMMAND,
            "--idempotency-key",
            "cli-key-01",
            "--mode",
            "risk_based",
            "--expected-revision",
            "9",
            "--preset-version",
            "2",
            "--expires-at-unix-ms",
            "none",
        ],
        &[
            "mode",
            "set",
            "--workspace-id",
            WORKSPACE,
            "--command-id",
            COMMAND,
            "--idempotency-key",
            "cli-key-01",
            "--mode",
            "ask_always",
            "--expected-revision",
            "9",
            "--preset-version",
            "1",
            "--expires-at-unix-ms",
            "0",
        ],
        &[
            "status",
            "--workspace-id",
            "5d3a7c8e-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
        ],
    ];
    for values in cases {
        assert!(
            matches!(parse_permissions(args(values)), Err(CliError::Usage)),
            "{values:?}"
        );
    }
}
#[test]
fn help_path_routes_only_commands_currently_implemented() {
    assert_eq!(help_for(&["permissions"]), PERMISSIONS_HELP);
    assert_eq!(
        help_for(&["permissions", "status"]),
        PERMISSIONS_STATUS_HELP
    );
    assert_eq!(
        help_for(&["permissions", "command", "status"]),
        PERMISSIONS_COMMAND_STATUS_HELP
    );
    assert_eq!(
        help_for(&["permissions", "approvals", "list"]),
        PERMISSIONS_APPROVALS_LIST_HELP
    );
    assert_eq!(
        help_for(&["permissions", "mode", "set"]),
        PERMISSIONS_MODE_SET_HELP
    );
}
#[test]
fn help_argument_is_closed_before_any_runtime_connection() {
    assert!(matches!(
        parse_permissions(args(&["--help"])),
        Err(CliError::Help(text)) if text == PERMISSIONS_HELP
    ));
    assert!(matches!(
        parse_permissions(args(&["status", "--help"])),
        Err(CliError::Help(text)) if text == PERMISSIONS_STATUS_HELP
    ));
    assert!(matches!(
        parse_permissions(args(&["mode", "set", "--help"])),
        Err(CliError::Help(text)) if text == PERMISSIONS_MODE_SET_HELP
    ));
}

#[test]
fn unknown_command_outcome_has_a_distinct_machine_exit_code() {
    assert_eq!(ErrorCode::CommandOutcomeUnknown.exit_code(), 5);
}

#[test]
fn permission_mode_human_labels_match_the_trusted_native_warning() {
    use runne_runtime_client::PermissionModeV1 as Mode;
    let cases = [
        (Mode::AskAlways, "Запрашивать разрешение"),
        (Mode::RiskBased, "Подтверждать за меня"),
        (Mode::FullAccess, "Полный доступ"),
    ];
    for (mode, expected) in cases {
        assert_eq!(permission_mode_label(mode), expected);
    }
}
