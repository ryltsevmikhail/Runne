use std::path::Path;

use runne_runtime_client::{
    AuthenticatedRuntimeClient, BindWorkspaceRootRequest, CanonicalId, CommandIdentity,
    ProjectTrustControlRequestDto, ProjectTrustControlSnapshotDto, ProjectTrustDecisionDto,
    ProjectTrustStatusDto, ProtectedRootAdmission, RuntimeApiErrorKind,
};

pub(super) async fn grant_through_public_control(
    client: &AuthenticatedRuntimeClient,
    project_id: CanonicalId,
    workspace_id: CanonicalId,
) -> ProjectTrustControlSnapshotDto {
    let observed = client
        .get_project_trust(project_id, workspace_id)
        .await
        .expect("public safe trust snapshot");
    let request = ProjectTrustControlRequestDto {
        project_id,
        workspace_id,
        decision: ProjectTrustDecisionDto::ConfirmProject,
        expected_epoch: observed.epoch(),
        expected_revision: observed.revision(),
        expected_project_version: observed.project_version(),
        expected_workspace_version: observed.workspace_version(),
        expected_root_admission_version: observed.root_admission_version(),
    };
    assert!(request.expected_root_admission_version.is_some());
    let confirmed = client
        .decide_project_trust(request)
        .await
        .expect("explicit protected project trust control");
    assert_eq!(confirmed.status(), ProjectTrustStatusDto::Trusted);
    let stale = client
        .decide_project_trust(ProjectTrustControlRequestDto {
            project_id,
            workspace_id,
            decision: ProjectTrustDecisionDto::ConfirmProject,
            expected_epoch: confirmed.epoch(),
            expected_revision: confirmed.revision() - 1,
            expected_project_version: confirmed.project_version(),
            expected_workspace_version: confirmed.workspace_version(),
            expected_root_admission_version: confirmed.root_admission_version(),
        })
        .await
        .expect_err("a stale replay cannot write trust twice");
    assert_eq!(stale.kind(), RuntimeApiErrorKind::Conflict);
    let after_replay = client
        .get_project_trust(project_id, workspace_id)
        .await
        .expect("authoritative trust readback");
    assert_eq!(after_replay.revision(), confirmed.revision());
    confirmed
}

pub(super) async fn assert_rebound_root_conflicts(
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    client: &AuthenticatedRuntimeClient,
    temporary: &Path,
    project_id: CanonicalId,
    workspace_id: CanonicalId,
    workspace_api_id: runne_api::WorkspaceId,
    old_root_version: u64,
) {
    let rebound_directory = temporary.join("rebound-project");
    super::t1_support::seed_hostile_workspace(&rebound_directory);
    let rebound_root = runne_platform_desktop::VerifiedRootHandle::open(&rebound_directory)
        .expect("open second synthetic root handle");
    let current_workspace = client
        .get_workspace(workspace_id)
        .await
        .expect("current workspace before rebind");
    let admission = supervisor
        .prepare_root_admission(&rebound_root, workspace_api_id, current_workspace.version())
        .expect("prepare rebind admission");
    let admission =
        ProtectedRootAdmission::from_verified(admission).expect("wrap second protected admission");
    let identity = CommandIdentity::new(
        CanonicalId::now_v7(),
        format!("t1-rebind-{}", CanonicalId::now_v7()),
    )
    .expect("rebind command identity");
    client
        .bind_workspace_root(
            BindWorkspaceRootRequest::new(
                identity,
                workspace_id,
                current_workspace.version(),
                &admission,
            )
            .expect("rebind request"),
        )
        .await
        .expect("bind second retained root");
    let rebound = client
        .get_project_trust(project_id, workspace_id)
        .await
        .expect("read trust after root rebind");
    assert_ne!(rebound.root_admission_version(), Some(old_root_version));
    let stale = client
        .decide_project_trust(ProjectTrustControlRequestDto {
            project_id,
            workspace_id,
            decision: ProjectTrustDecisionDto::ConfirmProject,
            expected_epoch: rebound.epoch(),
            expected_revision: rebound.revision(),
            expected_project_version: rebound.project_version(),
            expected_workspace_version: rebound.workspace_version(),
            expected_root_admission_version: Some(old_root_version),
        })
        .await
        .expect_err("confirmation cannot reuse the previous root admission version");
    assert_eq!(stale.kind(), RuntimeApiErrorKind::Conflict);
    let readback = client
        .get_project_trust(project_id, workspace_id)
        .await
        .expect("read trust after stale-root conflict");
    assert_eq!(readback.revision(), rebound.revision());
}

pub(super) fn assert_persistence_sinks(
    provider_root: &Path,
    desktop_db: &Path,
    scanner: &super::secret_scan::SecretScanner,
) {
    assert_eq!(
        std::fs::read_to_string(provider_root.join("fixture-provider-request-count"))
            .expect("fixture request count"),
        "3"
    );
    let receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(provider_root.join("fixture-provider-wire-scan-receipt.json"))
            .expect("T1 wire scan receipt"),
    )
    .expect("safe scan receipt JSON");
    assert!(receipt["requestByteCount"].as_u64().unwrap_or_default() > 0);
    assert!(receipt["responseByteCount"].as_u64().unwrap_or_default() > 0);
    assert_eq!(receipt["requestCanaryFree"], true);
    assert_eq!(receipt["responseCanaryFree"], true);
    assert_eq!(receipt["responseSent"], true);
    assert_eq!(receipt["requestSha256"].as_str().unwrap().len(), 64);
    assert_eq!(receipt["responseSha256"].as_str().unwrap().len(), 64);

    super::assert_tree_absent(
        "protected T1 daemon persistence sinks",
        &provider_root.join("runne-daemon"),
        scanner,
    );
    for artifact in [
        "fixture-provider-request-count",
        "fixture-provider-connection-count",
        "fixture-provider-wire-scan-receipt.json",
    ] {
        super::secret_scan::assert_file_absent(scanner, artifact, &provider_root.join(artifact));
    }
    super::t1_support::assert_profile_sqlite_absent(scanner, "AppCore profile", desktop_db);
}
