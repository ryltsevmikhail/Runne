use std::path::PathBuf;

const MARKER_FILE: &str = ".runne-test-protected-local-preapproval-stage";
const STAGES: &[&str] = &[
    "admission",
    "open_held_files",
    "sealed_snapshot",
    "preflight",
    "digest",
    "managed_area_support",
    "current_managed_identity_mismatch",
    "current_legacy_identity_rejected",
    "ready",
    "current_approval_wait",
    "current_effective_mode_rejected",
    "current_invocation_scope_rejected",
    "current_managed_disposition_missing",
    "current_policy_denied",
    "current_admission_store_failed",
    "current_approval_request_invalid",
    "current_approval_review_rejected",
    "current_approval_summary_invalid",
    "current_approval_state_rejected",
    "current_approval_expired",
    "current_approval_task_not_running",
    "current_approval_rejected",
    "current_release_before",
    "current_release_failed",
    "current_release_done",
    "current_rejection_stale",
    "current_approval_other_error",
];

pub(super) fn seed_legacy_selection(
    worker: &super::DaemonAutomaticTaskRuns,
    scope: &runne_application::permission_modes::PermissionScope,
    project: runne_application::project_trust::ProjectTrustProjectId,
    lease: &dyn runne_application::project_trust::ProjectTrustEffectLease,
) {
    let enabled = |name: &str| std::env::var_os(name).as_deref() == Some(std::ffi::OsStr::new("1"));
    if !enabled("RUNNE_TEST_T1_TRUST_COMPOSITION")
        || !enabled("RUNNE_TEST_T1_LOCAL_LEGACY_SELECTION")
    {
        return;
    }

    use runne_application::permission_modes::managed_policy_semantics_digest;
    use runne_application::permission_modes::{
        EffectiveModeHistoryState, ModeSelection, NetworkState, NotReadyReason, PermissionMode,
        PermissionModeHistoryProjection, PresetVersion, SetPermissionModeCommand,
    };
    use runne_domain::id::{CommandId, IdempotencyKey, IntegrityDigest};
    use runne_store::store::{ManagedIdentityMetadata, PermissionModeAuthorityContext};

    let principal = &scope.principal_id;
    let initial = worker
        .store
        .load_permission_mode_selection(scope, principal)
        .expect("read default selection before legacy test seed");
    assert_eq!(initial, ModeSelection::missing(scope.clone()));

    let record = lease.record();
    let managed_digest = managed_policy_semantics_digest(project, record);
    let authority = PermissionModeAuthorityContext::new(principal, project, lease, None);
    let mut command = SetPermissionModeCommand {
        command_id: CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes()),
        scope: scope.clone(),
        expected_authorization_revision: 0,
        requested_mode: PermissionMode::RiskBased,
        preset_version: PresetVersion::V1,
        intent_digest: IntegrityDigest::from_bytes([0; 32]),
        idempotency_key: IdempotencyKey::new(format!(
            "t1-legacy-selection-{}",
            uuid::Uuid::now_v7()
        ))
        .expect("construct test-only legacy selection idempotency key"),
        expires_at_unix_ms: None,
        managed_policy_version: record.revision,
        managed_policy_digest: managed_digest,
        challenge_binding_digest: None,
        challenge_expires_at_unix_ms: None,
        verified_native_challenge: None,
    };
    command.intent_digest = command.computed_intent_digest();
    let history = PermissionModeHistoryProjection {
        selected_mode: PermissionMode::RiskBased,
        effective: EffectiveModeHistoryState::NotReady(NotReadyReason::NativeContainment),
        authorization_revision: 1,
        preset_version: PresetVersion::V1,
        managed_policy_version: record.revision,
        containment: None,
        network_state: NetworkState::Unavailable,
        expires_at_unix_ms: None,
    };
    worker
        .store
        .commit_permission_mode_change(command, &authority, history)
        .expect("canonically seed V1 legacy selection for local-command fixture");

    let selected = worker
        .store
        .load_permission_mode_selection_with_managed_identity(scope, principal, &authority)
        .expect("read back canonical V1 legacy selection");
    assert_eq!(selected.selection.selected_mode, PermissionMode::RiskBased);
    assert_eq!(selected.selection.authorization_revision, 1);
    assert!(matches!(
        selected.identity,
        ManagedIdentityMetadata::LegacyRecordV1(identity)
            if identity.project_id == *project.as_bytes()
                && identity.managed_policy_version == record.revision
                && identity.managed_policy_digest == managed_digest
    ));
}

pub(super) fn begin() {
    if let Some(path) = marker_path() {
        let _ = std::fs::remove_file(path);
    }
}

pub(super) fn stage(stage: &'static str) {
    if !STAGES.contains(&stage) {
        return;
    }
    if let Some(path) = marker_path() {
        // Test-support only: keep the whole stage trace (bounded) so a failed
        // fixture can report the exact branch sequence, not just the last
        // stage. Each daemon writes at most one line per stage.
        let trace = std::fs::read_to_string(&path).unwrap_or_default();
        if trace.len() < 2048 {
            let _ = std::fs::write(&path, format!("{trace}{stage}\n"));
        }
    }
}

fn marker_path() -> Option<PathBuf> {
    let enabled = std::env::var_os("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    enabled.then(|| {
        std::env::var_os("RUNNE_TEST_PROTECTED_RUNTIME_ROOT")
            .map(PathBuf::from)
            .map(|root| root.join(MARKER_FILE))
    })?
}
