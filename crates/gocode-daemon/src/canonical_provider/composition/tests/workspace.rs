use gocode_application::ports::ProjectWorkspaceRepository;
use gocode_domain::{
    id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId},
    project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace},
};
use gocode_store::{ProjectWorkspaceStore, store::StoreTransaction};

pub(super) fn seed_canonical_workspace(store: &StoreTransaction, workspace_id: WorkspaceId) {
    let project_id = ProjectId::from_bytes([
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x11,
    ]);
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    repository
        .create_project(
            "local-owner",
            CommandId::from_bytes([
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x12,
            ]),
            &IdempotencyKey::new("provider-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Provider project".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            "local-owner",
            CommandId::from_bytes([
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x13,
            ]),
            &IdempotencyKey::new("provider-workspace").unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Provider workspace".into()).unwrap(),
            ),
        )
        .unwrap();
}
