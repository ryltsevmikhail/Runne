use super::*;

#[tokio::test]
async fn project_pages_are_bounded_stable_and_exclusive() {
    let (directory, host) = test_host();
    let owner = principal("owner");
    let expected = [20, 21, 22, 23, 24].map(project_id).to_vec();
    for tail in [20, 21, 22, 23, 24] {
        host.create_project(
            context(owner.clone(), &command_id(tail), &format!("project-{tail}")),
            CreateProjectCommand {
                project_id: project_id(tail),
                display_name: name("Page"),
            },
        )
        .await
        .unwrap();
    }
    let first = host
        .list_projects(
            ProjectQueryContext {
                principal: owner.clone(),
            },
            ProjectPageRequest::new(2, None).unwrap(),
        )
        .await
        .unwrap();
    let second = host
        .list_projects(
            ProjectQueryContext {
                principal: owner.clone(),
            },
            ProjectPageRequest::new(2, first.next_cursor).unwrap(),
        )
        .await
        .unwrap();
    let third = host
        .list_projects(
            ProjectQueryContext { principal: owner },
            ProjectPageRequest::new(2, second.next_cursor).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        [first.items.len(), second.items.len(), third.items.len()],
        [2, 2, 1]
    );
    let actual = first
        .items
        .iter()
        .chain(&second.items)
        .chain(&third.items)
        .map(|item| item.project_id)
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert!(third.next_cursor.is_none());
    let empty = host
        .list_projects(
            ProjectQueryContext {
                principal: principal("empty"),
            },
            ProjectPageRequest::new(2, None).unwrap(),
        )
        .await
        .unwrap();
    assert!(empty.items.is_empty());
    assert!(empty.next_cursor.is_none());
    assert_eq!(
        ProjectPageRequest::new(0, None),
        Err(ProjectWorkspaceHostError::Conflict)
    );
    assert_eq!(
        ProjectPageRequest::new(gocode_api::MAX_PROJECT_WORKSPACE_PAGE_SIZE + 1, None),
        Err(ProjectWorkspaceHostError::Conflict)
    );

    let database = support::database_path(&directory);
    host.shutdown().await;
    drop(host);
    let reopened = support::host_for(support::repository_at(&database));
    let reopened_first = reopened
        .list_projects(
            ProjectQueryContext {
                principal: principal("owner"),
            },
            ProjectPageRequest::new(2, None).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        reopened_first
            .items
            .into_iter()
            .map(|item| item.project_id)
            .collect::<Vec<_>>(),
        expected[..2]
    );
}

fn workspace_id(tail: u8) -> WorkspaceId {
    WorkspaceId::from_bytes([tail; 16])
}

#[tokio::test]
async fn workspace_pages_are_complete_and_cursors_are_project_and_principal_bound() {
    let (directory, host) = test_host();
    let owner = principal("workspace-owner");
    let project = project_id(30);
    let other_project = project_id(31);
    for (tail, id) in [(30, project), (31, other_project)] {
        host.create_project(
            context(
                owner.clone(),
                &command_id(tail),
                &format!("workspace-project-{tail}"),
            ),
            CreateProjectCommand {
                project_id: id,
                display_name: name("Workspace page"),
            },
        )
        .await
        .unwrap();
    }
    let expected = [40, 41, 42, 43, 44].map(workspace_id).to_vec();
    for tail in [40, 41, 42, 43, 44] {
        host.create_workspace(
            context(
                owner.clone(),
                &command_id(tail),
                &format!("workspace-{tail}"),
            ),
            CreateWorkspaceCommand {
                workspace_id: workspace_id(tail),
                project_id: project,
                display_name: name("Workspace"),
            },
        )
        .await
        .unwrap();
    }
    let query = ProjectQueryContext {
        principal: owner.clone(),
    };
    let first = host
        .list_workspaces(
            query.clone(),
            project,
            WorkspacePageRequest::new(2, None).unwrap(),
        )
        .await
        .unwrap();
    let first_cursor = first.next_cursor;
    let second = host
        .list_workspaces(
            query.clone(),
            project,
            WorkspacePageRequest::new(2, first.next_cursor).unwrap(),
        )
        .await
        .unwrap();
    let third = host
        .list_workspaces(
            query.clone(),
            project,
            WorkspacePageRequest::new(2, second.next_cursor).unwrap(),
        )
        .await
        .unwrap();
    let actual = first
        .items
        .iter()
        .chain(&second.items)
        .chain(&third.items)
        .map(|item| item.workspace_id)
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert!(third.next_cursor.is_none());

    let empty = host
        .list_workspaces(
            query.clone(),
            other_project,
            WorkspacePageRequest::new(2, None).unwrap(),
        )
        .await
        .unwrap();
    assert!(empty.items.is_empty());
    assert!(empty.next_cursor.is_none());
    assert_eq!(
        host.list_workspaces(
            query,
            other_project,
            WorkspacePageRequest::new(2, first_cursor).unwrap(),
        )
        .await
        .err(),
        Some(ProjectWorkspaceHostError::NotFound)
    );
    assert_eq!(
        host.list_workspaces(
            ProjectQueryContext {
                principal: principal("foreign")
            },
            project,
            WorkspacePageRequest::new(2, first_cursor).unwrap(),
        )
        .await
        .err(),
        Some(ProjectWorkspaceHostError::NotFound)
    );
    assert_eq!(
        WorkspacePageRequest::new(0, None),
        Err(ProjectWorkspaceHostError::Conflict)
    );
    assert_eq!(
        WorkspacePageRequest::new(gocode_api::MAX_PROJECT_WORKSPACE_PAGE_SIZE + 1, None),
        Err(ProjectWorkspaceHostError::Conflict)
    );

    let database = support::database_path(&directory);
    host.shutdown().await;
    drop(host);
    let reopened = support::host_for(support::repository_at(&database));
    let reopened_second = reopened
        .list_workspaces(
            ProjectQueryContext {
                principal: principal("workspace-owner"),
            },
            project,
            WorkspacePageRequest::new(2, first_cursor).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        reopened_second
            .items
            .into_iter()
            .map(|item| item.workspace_id)
            .collect::<Vec<_>>(),
        expected[2..4]
    );
}
