use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    read_watch: &std::fs::File,
    create_watch: &std::fs::File,
    created: &std::path::Path,
) {
    let approval = super::flows::wait_approval(client, task, database, runtime_root).await;
    super::flows::decide(
        client,
        &approval,
        runne_runtime_client::ApprovalDecisionDto::Approve,
        "revoke-before-lease",
    )
    .await
    .expect("approve exact D2 read before revocation");
    let directory = super::barriers::barrier_dir();
    wait_file(&directory.join("approved-before-lease.entered")).await;

    let workspace = client
        .get_workspace(workspace_id)
        .await
        .expect("read governed workspace");
    let current = client
        .get_project_trust(workspace.project_id(), workspace_id)
        .await
        .expect("read current trusted project revision");
    assert_eq!(
        current.status(),
        runne_runtime_client::ProjectTrustStatusDto::Trusted
    );
    let revoked = client
        .decide_project_trust(runne_runtime_client::ProjectTrustControlRequestDto {
            project_id: workspace.project_id(),
            workspace_id,
            decision: runne_runtime_client::ProjectTrustDecisionDto::RevokeProject,
            expected_epoch: current.epoch(),
            expected_revision: current.revision(),
            expected_project_version: current.project_version(),
            expected_workspace_version: current.workspace_version(),
            expected_root_admission_version: None,
        })
        .await;
    let revoked = match revoked {
        Ok(snapshot) => snapshot,
        Err(error)
            if error.kind() == runne_runtime_client::RuntimeApiErrorKind::UnknownAfterSend =>
        {
            client
                .get_project_trust(workspace.project_id(), workspace_id)
                .await
                .expect("read back possibly committed trust revocation")
        }
        Err(error) => panic!("public CAS trust revocation failed: {error:?}"),
    };
    assert_eq!(
        revoked.status(),
        runne_runtime_client::ProjectTrustStatusDto::Untrusted
    );
    assert_eq!(revoked.project_id(), current.project_id());
    assert_eq!(revoked.workspace_id(), current.workspace_id());
    assert_eq!(revoked.epoch(), current.epoch());
    assert_eq!(revoked.revision(), current.revision() + 1);
    assert_eq!(revoked.project_version(), current.project_version());
    assert_eq!(revoked.workspace_version(), current.workspace_version());
    assert_eq!(revoked.root_admission_version(), None);
    super::barriers::release("approved-before-lease");

    assert_eq!(
        super::flows::wait_terminal(client, task, database, runtime_root).await,
        runne_runtime_client::TaskRunState::Failed
    );
    super::database::assert_failure_projection(database, task);
    assert_eq!(
        super::database::invocation_state(database, task),
        "approved"
    );
    assert_eq!(super::database::result_count(database, task), 0);
    assert_eq!(super::database::release_intent_count(database, task), 0);
    assert_eq!(
        super::database::managed_area_launch_count(database, task),
        0
    );
    assert_eq!(count_watch_mask(read_watch, libc::IN_OPEN), 0);
    assert_eq!(count_watch_mask(create_watch, libc::IN_CREATE), 0);
    assert!(!created.exists());
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    assert_eq!(
        client
            .get_project_trust(workspace.project_id(), workspace_id)
            .await
            .expect("read committed project revocation")
            .status(),
        runne_runtime_client::ProjectTrustStatusDto::Untrusted
    );
    eprintln!("PASS: public trust revocation committed before lease and denied GO");
}

async fn wait_file(path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    while !path.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "pre-lease trust barrier not reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
