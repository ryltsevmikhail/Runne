use std::sync::atomic::{AtomicUsize, Ordering};

use runne_api::{ApiPrincipalId, ApprovalSummary};
#[cfg(target_os = "linux")]
use runne_application::ports::ProjectWorkspaceRepository;
use runne_application::{
    permission_modes::{
        CompositeEffectScope, ContainmentStrategy, EffectiveModeState, ModeSelection,
        NativeAdmissionError, NativeScopeAdmissionPort, NetworkScope, NetworkState, NotReadyReason,
        PermissionMode, PermissionScope, PresetVersion,
    },
    ports::RuntimeAuthorityId,
    project_trust::{
        ManagedEffectPolicyV1, ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId,
        ProjectTrustRecord, ProjectTrustStatus,
    },
};
use runne_domain::id::{ApprovalId, IntegrityDigest, InvocationId, TaskRunId, WorkspaceId};
#[cfg(target_os = "linux")]
use runne_domain::{
    id::{CommandId, IdempotencyKey, ProjectId},
    project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace},
};
#[cfg(target_os = "linux")]
use runne_store::store::{
    ClosedRulesManagedIdentityV2, ManagedIdentityMetadata, PermissionModeSelectionManagedIdentity,
};
#[cfg(target_os = "linux")]
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};

use super::{
    ProjectionMetadata, ProjectionTarget, current_projection, local_command_scope, observe_scope,
    pending_ids_for_workspace,
};

struct CountingAdmission {
    readiness: AtomicUsize,
    invocation: AtomicUsize,
}

impl CountingAdmission {
    fn new() -> Self {
        Self {
            readiness: AtomicUsize::new(0),
            invocation: AtomicUsize::new(0),
        }
    }
}

impl NativeScopeAdmissionPort for CountingAdmission {
    fn admit_mode_readiness(
        &self,
        _mode: PermissionMode,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        self.readiness.fetch_add(1, Ordering::SeqCst);
        Ok(digest(41))
    }

    fn admit_scope(
        &self,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        self.invocation.fetch_add(1, Ordering::SeqCst);
        Ok(digest(42))
    }
}

struct UnavailableAdmission(AtomicUsize);

impl NativeScopeAdmissionPort for UnavailableAdmission {
    fn admit_mode_readiness(
        &self,
        _mode: PermissionMode,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(NativeAdmissionError::EnforcementUnavailable)
    }

    fn admit_scope(
        &self,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        panic!("current projection must not admit an invocation")
    }
}

fn digest(byte: u8) -> IntegrityDigest {
    IntegrityDigest::from_bytes([byte; 32])
}

fn workspace(byte: u8) -> WorkspaceId {
    WorkspaceId::from_bytes([byte; 16])
}

fn permission_scope(workspace_id: WorkspaceId) -> PermissionScope {
    PermissionScope {
        runtime_authority_id: RuntimeAuthorityId("runtime-projection-test".into()),
        principal_id: ApiPrincipalId::new("user:projection-test").unwrap(),
        workspace_id,
    }
}

fn selection(mode: PermissionMode, revision: u64, expiry: Option<i64>) -> ModeSelection {
    ModeSelection {
        scope: permission_scope(workspace(3)),
        selected_mode: mode,
        preset_version: PresetVersion::V1,
        authorization_revision: revision,
        expires_at_unix_ms: expiry,
    }
}

fn trust_snapshot(revision: u64) -> ProjectTrustEffectPolicySnapshot {
    ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Trusted,
            instance_epoch: 7,
            revision,
            managed_deny_mask: 0,
        },
        policy: ManagedEffectPolicyV1::all_allow(),
    }
}

#[cfg(target_os = "linux")]
fn managed_identity(
    selection: ModeSelection,
    revision: u64,
    policy_digest: IntegrityDigest,
) -> PermissionModeSelectionManagedIdentity {
    PermissionModeSelectionManagedIdentity {
        selection,
        identity: ManagedIdentityMetadata::ClosedRulesV2(ClosedRulesManagedIdentityV2 {
            project_id: [9; 16],
            project_version: 2,
            snapshot: trust_snapshot(revision),
            canonical_digest: policy_digest,
            challenge_binding: None,
        }),
    }
}

#[test]
fn current_projection_released_gate_runs_native_probe_and_maps_result() {
    let selected = selection(PermissionMode::FullAccess, 4, None);
    let scope = local_command_scope(
        &selected,
        selected.scope.clone(),
        ProjectTrustProjectId::from_bytes([9; 16]),
        &trust_snapshot(8),
        digest(46),
    )
    .unwrap();
    let observed = observe_scope(&selected, &scope, &CountingAdmission::new(), 100).unwrap();
    let expected_effective = observed.effective.clone();
    let called = AtomicUsize::new(0);
    let projection = current_projection(
        ProjectionMetadata {
            selection: selected.clone(),
            managed_policy_version: 8,
        },
        || {
            called.fetch_add(1, Ordering::SeqCst);
            Ok(observed)
        },
    );
    assert_eq!(called.load(Ordering::SeqCst), 1);
    assert_eq!(projection.effective, expected_effective);
    assert!(matches!(projection.effective, EffectiveModeState::Ready(_)));
    assert_eq!(
        projection.containment,
        Some(ContainmentStrategy::SameUserCompositeV1)
    );
    assert_eq!(projection.network_state, NetworkState::BroadSameUser);
    assert_eq!(projection.authorization_revision, 4);

    let failed = current_projection(
        ProjectionMetadata {
            selection: selected,
            managed_policy_version: 8,
        },
        || Err(NotReadyReason::PresetUnavailable),
    );
    assert_eq!(
        failed.effective,
        EffectiveModeState::NotReady(NotReadyReason::PresetUnavailable)
    );
    assert_eq!(failed.containment, None);
    assert_eq!(failed.network_state, NetworkState::Unavailable);
    assert_eq!(failed.authorization_revision, 4);
}

#[test]
fn direct_core_probe_uses_full_access_network_and_never_admits_an_invocation() {
    let project = ProjectTrustProjectId::from_bytes([9; 16]);
    let trust = trust_snapshot(8);
    let native = CountingAdmission::new();
    for mode in [
        PermissionMode::AskAlways,
        PermissionMode::RiskBased,
        PermissionMode::FullAccess,
    ] {
        let selected = selection(mode, 2, None);
        let scope = local_command_scope(
            &selected,
            selected.scope.clone(),
            project,
            &trust,
            digest(43),
        )
        .unwrap();
        let full_access = mode == PermissionMode::FullAccess;
        assert_eq!(
            scope.network,
            if full_access {
                NetworkScope::BroadSameUser
            } else {
                NetworkScope::None
            }
        );
        let observed = observe_scope(&selected, &scope, &native, 100).unwrap();
        assert!(matches!(observed.effective, EffectiveModeState::Ready(_)));
        assert_eq!(
            observed.network_state,
            if full_access {
                NetworkState::BroadSameUser
            } else {
                NetworkState::Unavailable
            }
        );
    }
    assert_eq!(native.readiness.load(Ordering::SeqCst), 3);
    assert_eq!(native.invocation.load(Ordering::SeqCst), 0);
}

#[test]
fn unavailable_native_readiness_is_reported_without_invocation_admission() {
    let selected = selection(PermissionMode::RiskBased, 2, None);
    let trust = trust_snapshot(8);
    let scope = local_command_scope(
        &selected,
        selected.scope.clone(),
        ProjectTrustProjectId::from_bytes([9; 16]),
        &trust,
        digest(45),
    )
    .unwrap();
    let native = UnavailableAdmission(AtomicUsize::new(0));
    assert!(matches!(
        observe_scope(&selected, &scope, &native, 100),
        Err(NotReadyReason::NativeContainment)
    ));
    assert_eq!(native.0.load(Ordering::SeqCst), 1);
}

#[test]
fn expired_selection_is_rejected_before_native_readiness_admission() {
    let selected = selection(PermissionMode::RiskBased, 2, Some(99));
    let trust = trust_snapshot(8);
    let scope = local_command_scope(
        &selected,
        selected.scope.clone(),
        ProjectTrustProjectId::from_bytes([9; 16]),
        &trust,
        digest(44),
    )
    .unwrap();
    let native = CountingAdmission::new();
    assert!(matches!(
        observe_scope(&selected, &scope, &native, 100),
        Err(NotReadyReason::NativeContainment)
    ));
    assert_eq!(native.readiness.load(Ordering::SeqCst), 0);
}

#[test]
#[cfg(target_os = "linux")]
fn candidate_projection_rejects_revision_and_managed_policy_drift() {
    let selected = selection(PermissionMode::AskAlways, 3, None);
    let managed = managed_identity(selected.clone(), 8, digest(51));
    let ManagedIdentityMetadata::ClosedRulesV2(managed_rules) = &managed.identity else {
        unreachable!();
    };
    let candidate = ModeSelection {
        selected_mode: PermissionMode::FullAccess,
        authorization_revision: 4,
        ..selected.clone()
    };
    let target = ProjectionTarget::Candidate {
        selection: candidate.clone(),
        expected_revision: 3,
        managed_policy_version: 8,
        managed_policy_digest: digest(51),
    };
    assert_eq!(
        crate::application::permission_projection_runtime::selected_target(
            &target,
            &managed,
            managed_rules,
        ),
        Ok(candidate.clone())
    );

    let stale_revision = ProjectionTarget::Candidate {
        selection: candidate.clone(),
        expected_revision: 2,
        managed_policy_version: 8,
        managed_policy_digest: digest(51),
    };
    assert_eq!(
        crate::application::permission_projection_runtime::selected_target(
            &stale_revision,
            &managed,
            managed_rules,
        ),
        Err(NotReadyReason::NativeContainment)
    );
    let stale_policy = ProjectionTarget::Candidate {
        selection: candidate.clone(),
        expected_revision: 3,
        managed_policy_version: 9,
        managed_policy_digest: digest(51),
    };
    assert_eq!(
        crate::application::permission_projection_runtime::selected_target(
            &stale_policy,
            &managed,
            managed_rules,
        ),
        Err(NotReadyReason::NativeContainment)
    );
    let changed_digest = ProjectionTarget::Candidate {
        selection: candidate,
        expected_revision: 3,
        managed_policy_version: 8,
        managed_policy_digest: digest(52),
    };
    assert_eq!(
        crate::application::permission_projection_runtime::selected_target(
            &changed_digest,
            &managed,
            managed_rules,
        ),
        Err(NotReadyReason::NativeContainment)
    );
}

#[test]
fn pending_approvals_follow_canonical_taskrun_workspace_for_every_action() {
    let target_workspace = workspace(1);
    let other_workspace = workspace(2);
    let target_run_a = TaskRunId::from_bytes([11; 16]);
    let target_run_b = TaskRunId::from_bytes([12; 16]);
    let other_run = TaskRunId::from_bytes([13; 16]);
    let approvals = vec![
        pending_summary(
            1,
            target_run_a,
            "local_command.execute",
            "stale/untrusted/resource",
        ),
        pending_summary(2, target_run_b, "filesystem.write", "unrelated/resource"),
        pending_summary(3, other_run, "permission.change", "workspace:wrong"),
    ];
    let found =
        pending_ids_for_workspace(
            approvals,
            target_workspace,
            |task_run_id| match task_run_id {
                id if id == target_run_a || id == target_run_b => Ok(Some(target_workspace)),
                id if id == other_run => Ok(Some(other_workspace)),
                _ => Ok(None),
            },
        )
        .unwrap();
    assert_eq!(
        found,
        vec![
            ApprovalId::from_bytes([1; 16]),
            ApprovalId::from_bytes([2; 16])
        ]
    );
}

#[test]
fn pending_status_fails_closed_when_taskrun_lookup_fails() {
    let approvals = vec![pending_summary(
        4,
        TaskRunId::from_bytes([14; 16]),
        "local_command.execute",
        "resource",
    )];
    assert_eq!(
        pending_ids_for_workspace(approvals, workspace(1), |_| {
            Err(super::PendingApprovalScopeUnavailable)
        }),
        Err(super::PendingApprovalScopeUnavailable)
    );
}

fn pending_summary(
    id: u8,
    task_run_id: TaskRunId,
    action: &str,
    resource: &str,
) -> ApprovalSummary {
    ApprovalSummary::try_new(
        ApprovalId::from_bytes([id; 16]),
        task_run_id,
        None,
        InvocationId::from_bytes([id; 16]),
        action,
        resource,
        [id; 32],
        1,
        1,
        1,
        1000,
        "pending",
    )
    .unwrap()
}

#[test]
fn canonical_root_binding_rejects_workspace_close_rebind_and_version_drift() {
    use crate::application::permission_projection_runtime::workspace_binding_matches;

    assert!(workspace_binding_matches(7, true, [3; 16], (7, [3; 16])));
    assert!(!workspace_binding_matches(8, true, [3; 16], (7, [3; 16])));
    assert!(!workspace_binding_matches(7, false, [3; 16], (7, [3; 16])));
    assert!(!workspace_binding_matches(7, true, [4; 16], (7, [3; 16])));
}

#[test]
#[cfg(target_os = "linux")]
fn project_rename_invalidates_projection_without_changing_workspace_version() {
    use crate::application::permission_projection_runtime::ensure_project_version;

    let directory = tempfile::tempdir().expect("temporary projection store");
    let daemon_directory = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon_directory).expect("private store directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&daemon_directory, std::fs::Permissions::from_mode(0o700))
            .expect("private store permissions");
    }
    let path = daemon_directory.join("projection.db");
    let store = StoreTransaction::open(
        path.to_str().expect("database path"),
        RuntimeAuthorityId("runtime-projection-test".into()),
        std::sync::Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
    )
    .expect("projection store");
    let workspaces = ProjectWorkspaceStore::from_store(store);
    let principal = ApiPrincipalId::new("user:projection-test").unwrap();
    let project_id = ProjectId::from_bytes([71; 16]);
    let workspace_id = workspace(72);

    workspaces
        .create_project(
            principal.as_str(),
            CommandId::from_bytes([73; 16]),
            &IdempotencyKey::new("projection-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("before rename".into()).unwrap(),
            ),
        )
        .expect("project");
    workspaces
        .create_workspace(
            principal.as_str(),
            CommandId::from_bytes([74; 16]),
            &IdempotencyKey::new("projection-workspace").unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("workspace".into()).unwrap(),
            ),
        )
        .expect("workspace");
    let workspace_version = workspaces
        .get_workspace(principal.as_str(), workspace_id)
        .expect("workspace binding")
        .version();
    let project = workspaces
        .get_project(principal.as_str(), project_id)
        .expect("live project");
    assert!(!project.archived());
    let project_version = project.version();
    assert_eq!(
        ensure_project_version(
            &workspaces,
            &principal,
            *project_id.as_bytes(),
            project_version,
        ),
        Ok(())
    );

    workspaces
        .rename_project(
            principal.as_str(),
            CommandId::from_bytes([75; 16]),
            &IdempotencyKey::new("projection-rename").unwrap(),
            project_id,
            project_version,
            ProjectWorkspaceDisplayName::new("after rename".into()).unwrap(),
        )
        .expect("rename project");

    assert_eq!(
        workspaces
            .get_workspace(principal.as_str(), workspace_id)
            .expect("workspace binding")
            .version(),
        workspace_version
    );
    assert_eq!(
        ensure_project_version(
            &workspaces,
            &principal,
            *project_id.as_bytes(),
            project_version,
        ),
        Err(NotReadyReason::NativeContainment)
    );
    assert_eq!(
        ensure_project_version(
            &workspaces,
            &principal,
            *project_id.as_bytes(),
            project_version + 1,
        ),
        Ok(())
    );
}
