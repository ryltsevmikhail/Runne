use super::*;

pub(super) async fn confirm_rebound_project_trust(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    temporary_root: &std::path::Path,
    runtime_project_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    workspace_api_id: runne_api::WorkspaceId,
) {
    let initial = super::t1_trust_control::grant_through_public_control(
        client,
        runtime_project_id,
        workspace_id,
    )
    .await;
    let old_root_version = initial
        .root_admission_version()
        .expect("first root admission version");
    super::t1_trust_control::assert_rebound_root_conflicts(
        supervisor,
        client,
        temporary_root,
        runtime_project_id,
        workspace_id,
        workspace_api_id,
        old_root_version,
    )
    .await;
    let rebound = super::t1_trust_control::grant_through_public_control(
        client,
        runtime_project_id,
        workspace_id,
    )
    .await;
    assert_eq!(
        rebound.status(),
        runne_runtime_client::ProjectTrustStatusDto::Trusted,
        "the newly bound project root requires explicit trust before local approval"
    );
}
