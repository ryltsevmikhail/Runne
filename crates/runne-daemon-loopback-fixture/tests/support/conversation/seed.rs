use runne_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CreateProjectRequest, CreateWorkspaceRequest,
};

use super::{
    PROJECT_COMMAND_ID, PROJECT_IDEMPOTENCY_KEY, WORKSPACE_COMMAND_ID, WORKSPACE_IDEMPOTENCY_KEY,
    id, identity,
};

pub(super) async fn seed_workspace(
    client: &AuthenticatedRuntimeClient,
    project_id: CanonicalId,
    workspace_id: CanonicalId,
) {
    let project = client
        .create_project(
            CreateProjectRequest::new(
                identity(id(PROJECT_COMMAND_ID), PROJECT_IDEMPOTENCY_KEY),
                project_id,
                "Fixture project",
            )
            .expect("canonical Project request"),
        )
        .await
        .expect("create canonical Project");
    assert_eq!(project.project_id(), project_id);
    assert_eq!(project.new_version(), 1);
    let workspace = client
        .create_workspace(
            CreateWorkspaceRequest::new(
                identity(id(WORKSPACE_COMMAND_ID), WORKSPACE_IDEMPOTENCY_KEY),
                project_id,
                workspace_id,
                "Fixture workspace",
            )
            .expect("canonical Workspace request"),
        )
        .await
        .expect("create canonical Workspace");
    assert_eq!(workspace.workspace_id(), workspace_id);
    assert_eq!(workspace.new_version(), 1);
}
