use gocode_api::{
    MAX_PROJECT_WORKSPACE_PAGE_SIZE, ProjectPage, ProjectPageRequest, ProjectSnapshot,
    ProjectWorkspaceHostError, ProjectWorkspacePageSize, WorkspacePage, WorkspacePageRequest,
    WorkspaceSnapshot,
};
use gocode_domain::id::{ProjectId, WorkspaceId};

fn project_snapshot(value: u8) -> ProjectSnapshot {
    ProjectSnapshot {
        project_id: ProjectId::from_bytes([value; 16]),
        display_name: "Project".into(),
        version: 1,
        archived: false,
    }
}

fn workspace_snapshot(value: u8) -> WorkspaceSnapshot {
    WorkspaceSnapshot {
        workspace_id: WorkspaceId::from_bytes([value; 16]),
        project_id: ProjectId::from_bytes([1; 16]),
        display_name: "Workspace".into(),
        version: 1,
        open: false,
    }
}

#[test]
fn invalid_sizes_are_closed_for_both_repository_value_and_request_boundaries() {
    for value in [0, MAX_PROJECT_WORKSPACE_PAGE_SIZE + 1, u16::MAX] {
        assert_eq!(
            ProjectWorkspacePageSize::new(value),
            Err(ProjectWorkspaceHostError::Conflict)
        );
        assert_eq!(
            ProjectPageRequest::new(value, None),
            Err(ProjectWorkspaceHostError::Conflict)
        );
        assert_eq!(
            WorkspacePageRequest::new(value, None),
            Err(ProjectWorkspaceHostError::Conflict)
        );
    }
}

#[test]
fn page_construction_enforces_exact_bound_and_cursor_coherence() {
    let size = ProjectWorkspacePageSize::new(2).unwrap();
    assert_eq!(
        ProjectPage::new(size, vec![project_snapshot(1); 3], None),
        Err(ProjectWorkspaceHostError::InvariantViolation)
    );
    assert_eq!(
        ProjectPage::new(
            size,
            vec![project_snapshot(1), project_snapshot(2)],
            Some(ProjectId::from_bytes([1; 16])),
        ),
        Err(ProjectWorkspaceHostError::InvariantViolation)
    );
    let projects = ProjectPage::new(
        size,
        vec![project_snapshot(1), project_snapshot(2)],
        Some(ProjectId::from_bytes([2; 16])),
    )
    .unwrap();
    assert_eq!(projects.items().len(), 2);

    let project = ProjectId::from_bytes([1; 16]);
    assert_eq!(
        WorkspacePage::new(size, project, vec![workspace_snapshot(1); 3], None),
        Err(ProjectWorkspaceHostError::InvariantViolation)
    );
    assert_eq!(
        WorkspacePage::new(
            size,
            project,
            vec![workspace_snapshot(1), workspace_snapshot(2)],
            Some(WorkspaceId::from_bytes([1; 16])),
        ),
        Err(ProjectWorkspaceHostError::InvariantViolation)
    );
    let workspaces = WorkspacePage::new(
        size,
        project,
        vec![workspace_snapshot(1), workspace_snapshot(2)],
        Some(WorkspaceId::from_bytes([2; 16])),
    )
    .unwrap();
    assert_eq!(workspaces.items().len(), 2);
}
