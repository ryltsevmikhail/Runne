use runne_application::ports::ProjectWorkspaceRepository;
use runne_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};

pub fn seed_canonical_workspace(
    store: &StoreTransaction,
    principal: &str,
    workspace_id: WorkspaceId,
) {
    let project_id = ProjectId::from_bytes(derived(workspace_id.into_bytes(), 0xa1));
    let project_command = CommandId::from_bytes(derived(workspace_id.into_bytes(), 0xb1));
    let workspace_command = CommandId::from_bytes(derived(workspace_id.into_bytes(), 0xb2));
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    repository
        .create_project(
            principal,
            project_command,
            &IdempotencyKey::new(format!("fixture-project-{workspace_id}")).unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Fixture project".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            principal,
            workspace_command,
            &IdempotencyKey::new(format!("fixture-workspace-{workspace_id}")).unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Fixture workspace".into()).unwrap(),
            ),
        )
        .unwrap();
}

fn derived(mut value: [u8; 16], marker: u8) -> [u8; 16] {
    value[14] ^= marker;
    value
}
