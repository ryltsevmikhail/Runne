use super::*;

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
            Err(super::super::PendingApprovalScopeUnavailable)
        }),
        Err(super::super::PendingApprovalScopeUnavailable)
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
