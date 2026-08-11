use super::*;

fn assert_not_found<T>(result: Result<T, ProjectWorkspaceHostError>) {
    assert_eq!(result.err(), Some(ProjectWorkspaceHostError::NotFound));
}

#[tokio::test]
async fn foreign_and_absent_targets_are_indistinguishable_across_lifecycle_surfaces() {
    let (_directory, host) = test_host();
    let owner = principal("owner");
    let foreign = principal("foreign");
    let project = project_id(60);
    let workspace = WORKSPACE_ID.parse::<WorkspaceId>().unwrap();
    host.create_project(
        context(owner.clone(), &command_id(60), "nd-project"),
        CreateProjectCommand {
            project_id: project,
            display_name: name("Private"),
        },
    )
    .await
    .unwrap();
    host.create_workspace(
        context(owner, &command_id(61), "nd-workspace"),
        CreateWorkspaceCommand {
            workspace_id: workspace,
            project_id: project,
            display_name: name("Private workspace"),
        },
    )
    .await
    .unwrap();

    let missing_project = project_id(0xf0);
    let missing_workspace = WorkspaceId::from_bytes([0xf1; 16]);
    for hidden_principal in [foreign.clone(), principal("absent-principal")] {
        let page = host
            .list_projects(
                ProjectQueryContext {
                    principal: hidden_principal,
                },
                ProjectPageRequest::new(1, None).unwrap(),
            )
            .await
            .unwrap();
        assert!(page.items.is_empty());
        assert!(page.next_cursor.is_none());
    }
    assert_not_found(
        host.get_workspace(
            ProjectQueryContext {
                principal: foreign.clone(),
            },
            workspace,
        )
        .await,
    );
    assert_not_found(
        host.get_workspace(
            ProjectQueryContext {
                principal: foreign.clone(),
            },
            missing_workspace,
        )
        .await,
    );
    assert_not_found(
        host.list_workspaces(
            ProjectQueryContext {
                principal: foreign.clone(),
            },
            project,
            WorkspacePageRequest::new(1, None).unwrap(),
        )
        .await,
    );
    assert_not_found(
        host.list_workspaces(
            ProjectQueryContext {
                principal: foreign.clone(),
            },
            missing_project,
            WorkspacePageRequest::new(1, None).unwrap(),
        )
        .await,
    );

    for (tail, operation) in [(62, "archive"), (64, "restore"), (66, "delete")] {
        let existing = ExistingProjectCommand {
            project_id: project,
            expected_version: 1,
        };
        let absent = ExistingProjectCommand {
            project_id: missing_project,
            expected_version: 1,
        };
        let foreign_context = context(foreign.clone(), &command_id(tail), operation);
        let absent_context = context(
            foreign.clone(),
            &command_id(tail + 1),
            &format!("{operation}-absent"),
        );
        let (foreign_result, absent_result) = match operation {
            "archive" => (
                host.archive_project(foreign_context, existing).await,
                host.archive_project(absent_context, absent).await,
            ),
            "restore" => (
                host.restore_project(foreign_context, existing).await,
                host.restore_project(absent_context, absent).await,
            ),
            _ => (
                host.delete_project(foreign_context, existing).await,
                host.delete_project(absent_context, absent).await,
            ),
        };
        assert_not_found(foreign_result);
        assert_not_found(absent_result);
    }

    assert_not_found(
        host.create_workspace(
            context(foreign.clone(), &command_id(68), "create-foreign"),
            CreateWorkspaceCommand {
                workspace_id: WorkspaceId::from_bytes([0x68; 16]),
                project_id: project,
                display_name: name("Hidden"),
            },
        )
        .await,
    );
    assert_not_found(
        host.create_workspace(
            context(foreign.clone(), &command_id(69), "create-absent"),
            CreateWorkspaceCommand {
                workspace_id: WorkspaceId::from_bytes([0x69; 16]),
                project_id: missing_project,
                display_name: name("Hidden"),
            },
        )
        .await,
    );
    assert_not_found(
        host.open_workspace(
            context(foreign.clone(), &command_id(70), "open-foreign"),
            ExistingWorkspaceCommand {
                workspace_id: workspace,
                expected_version: 1,
            },
        )
        .await,
    );
    assert_not_found(
        host.open_workspace(
            context(foreign.clone(), &command_id(71), "open-absent"),
            ExistingWorkspaceCommand {
                workspace_id: missing_workspace,
                expected_version: 1,
            },
        )
        .await,
    );

    for (tail, workspace_id) in [(72, workspace), (73, missing_workspace)] {
        assert_not_found(
            host.bind_workspace_root(
                context(foreign.clone(), &command_id(tail), &format!("bind-{tail}")),
                BindWorkspaceRootCommand {
                    workspace_id,
                    expected_version: 1,
                    root_admission: gocode_api::test_support::admission(),
                },
            )
            .await,
        );
    }
}
