use gocode_api::{
    ApiActor, ApiPrincipalId, CreateProjectCommand, CreateWorkspaceCommand, ExistingProjectCommand,
    ProjectCommandContext, ProjectQueryContext, ProjectWorkspaceCommandHostPort,
    ProjectWorkspaceHostError, ProjectWorkspaceQueryHostPort,
};
use gocode_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use gocode_runtime::RuntimeProjectWorkspaceHost;
use gocode_store::ProjectWorkspaceStore;

const PROJECT_ID: &str = "018f47a2-4f8c-7b52-8c35-7a3a14c2d9e1";
const WORKSPACE_ID: &str = "018f47a2-4f8c-7b52-8c35-7a3a14c2d9e2";

fn principal(value: &str) -> ApiPrincipalId {
    ApiPrincipalId::new(value).unwrap()
}

fn context(principal: ApiPrincipalId, command: &str, key: &str) -> ProjectCommandContext {
    ProjectCommandContext {
        command_id: command.parse::<CommandId>().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal,
        actor: ApiActor::new("desktop").unwrap(),
    }
}

fn command_id(tail: u8) -> String {
    format!("018f47a2-4f8c-7b52-8c35-7a3a14c2d9{tail:02x}")
}

#[tokio::test]
async fn project_workspace_create_project_replays_the_exact_idempotent_acknowledgement() {
    let host = RuntimeProjectWorkspaceHost::new(ProjectWorkspaceStore::new());
    let owner = principal("owner");
    let request = CreateProjectCommand {
        project_id: PROJECT_ID.parse::<ProjectId>().unwrap(),
        display_name: "GOCODE".into(),
    };

    let first = host
        .create_project(
            context(owner.clone(), &command_id(1), "project-create"),
            request.clone(),
        )
        .await
        .unwrap();
    let replay = host
        .create_project(context(owner, &command_id(1), "project-create"), request)
        .await
        .unwrap();

    assert_eq!(first, replay);
    assert_eq!(first.new_version, 1);
}

#[tokio::test]
async fn project_workspace_queries_fail_closed_for_another_principal() {
    let host = RuntimeProjectWorkspaceHost::new(ProjectWorkspaceStore::new());
    let owner = principal("owner");
    let project_id = PROJECT_ID.parse::<ProjectId>().unwrap();
    host.create_project(
        context(owner, &command_id(2), "project-owner"),
        CreateProjectCommand {
            project_id,
            display_name: "Private".into(),
        },
    )
    .await
    .unwrap();

    let result = host
        .get_project(
            ProjectQueryContext {
                principal: principal("other"),
            },
            project_id,
        )
        .await;

    assert_eq!(result, Err(ProjectWorkspaceHostError::Forbidden));
}

#[tokio::test]
async fn project_workspace_rejects_workspace_creation_in_another_principals_project() {
    let host = RuntimeProjectWorkspaceHost::new(ProjectWorkspaceStore::new());
    let project_id = PROJECT_ID.parse::<ProjectId>().unwrap();
    host.create_project(
        context(principal("owner"), &command_id(8), "project-cross-owner"),
        CreateProjectCommand {
            project_id,
            display_name: "Owner project".into(),
        },
    )
    .await
    .unwrap();

    let result = host
        .create_workspace(
            context(
                principal("other"),
                &command_id(9),
                "workspace-cross-project",
            ),
            CreateWorkspaceCommand {
                workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
                project_id,
                display_name: "Rejected".into(),
            },
        )
        .await;

    assert_eq!(result, Err(ProjectWorkspaceHostError::Forbidden));
}

#[tokio::test]
async fn project_workspace_stale_project_version_is_rejected_exactly() {
    let host = RuntimeProjectWorkspaceHost::new(ProjectWorkspaceStore::new());
    let owner = principal("owner");
    let project_id = PROJECT_ID.parse::<ProjectId>().unwrap();
    host.create_project(
        context(owner.clone(), &command_id(3), "project-create-stale"),
        CreateProjectCommand {
            project_id,
            display_name: "Versioned".into(),
        },
    )
    .await
    .unwrap();

    let result = host
        .archive_project(
            context(owner, &command_id(4), "project-archive-stale"),
            ExistingProjectCommand {
                project_id,
                expected_version: 0,
            },
        )
        .await;

    assert_eq!(result, Err(ProjectWorkspaceHostError::Conflict));
}

#[tokio::test]
async fn project_workspace_archives_and_restores_at_exact_versions_idempotently() {
    let host = RuntimeProjectWorkspaceHost::new(ProjectWorkspaceStore::new());
    let owner = principal("owner");
    let project_id = PROJECT_ID.parse::<ProjectId>().unwrap();
    host.create_project(
        context(owner.clone(), &command_id(10), "restore-create"),
        CreateProjectCommand {
            project_id,
            display_name: "Restore".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        host.archive_project(
            context(owner.clone(), &command_id(11), "restore-archive"),
            ExistingProjectCommand {
                project_id,
                expected_version: 1
            },
        )
        .await
        .unwrap()
        .new_version,
        2
    );
    let restore_context = context(owner.clone(), &command_id(12), "restore-project");
    let restored = host
        .restore_project(
            restore_context.clone(),
            ExistingProjectCommand {
                project_id,
                expected_version: 2,
            },
        )
        .await
        .unwrap();
    let replay = host
        .restore_project(
            restore_context,
            ExistingProjectCommand {
                project_id,
                expected_version: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(restored, replay);
    assert_eq!(restored.new_version, 3);
    assert_eq!(
        host.restore_project(
            context(owner.clone(), &command_id(13), "restore-stale"),
            ExistingProjectCommand {
                project_id,
                expected_version: 2
            },
        )
        .await,
        Err(ProjectWorkspaceHostError::Conflict)
    );
    assert!(
        !host
            .get_project(ProjectQueryContext { principal: owner }, project_id)
            .await
            .unwrap()
            .archived
    );
}

#[tokio::test]
async fn project_workspace_project_cannot_be_deleted_while_it_owns_a_live_workspace() {
    let host = RuntimeProjectWorkspaceHost::new(ProjectWorkspaceStore::new());
    let owner = principal("owner");
    let project_id = PROJECT_ID.parse::<ProjectId>().unwrap();
    host.create_project(
        context(owner.clone(), &command_id(5), "project-delete-create"),
        CreateProjectCommand {
            project_id,
            display_name: "Live workspace".into(),
        },
    )
    .await
    .unwrap();
    host.create_workspace(
        context(owner.clone(), &command_id(6), "workspace-create"),
        CreateWorkspaceCommand {
            workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
            project_id,
            display_name: "One".into(),
        },
    )
    .await
    .unwrap();

    let result = host
        .delete_project(
            context(owner, &command_id(7), "project-delete"),
            ExistingProjectCommand {
                project_id,
                expected_version: 1,
            },
        )
        .await;

    assert_eq!(result, Err(ProjectWorkspaceHostError::Conflict));
}
