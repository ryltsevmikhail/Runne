use gocode_api::{
    ApiPrincipalId, MAX_PROJECT_WORKSPACE_PAGE_SIZE, PageCursorTokenError, ProjectPage,
    ProjectPageCursor, ProjectPageRequest, ProjectSnapshot, ProjectWorkspaceHostError,
    ProjectWorkspacePageSize, WorkspacePage, WorkspacePageCursor, WorkspacePageRequest,
    WorkspaceSnapshot,
};
use gocode_domain::id::{ProjectId, WorkspaceId};

fn project_snapshot(value: u8) -> ProjectSnapshot {
    ProjectSnapshot {
        project_id: project_id(value),
        display_name: "Project".into(),
        version: 1,
        archived: false,
    }
}

fn workspace_snapshot(value: u8) -> WorkspaceSnapshot {
    WorkspaceSnapshot {
        workspace_id: workspace_id(value),
        project_id: project_id(1),
        display_name: "Workspace".into(),
        version: 1,
        open: false,
    }
}

fn project_id(value: u8) -> ProjectId {
    format!("018f47a2-4f8c-7b52-8c35-7a3a14c2d9{value:02x}")
        .parse()
        .unwrap()
}

fn workspace_id(value: u8) -> WorkspaceId {
    format!("018f47a2-4f8c-7b52-8c35-7a3a14c2d8{value:02x}")
        .parse()
        .unwrap()
}

fn principal() -> ApiPrincipalId {
    ApiPrincipalId::new("owner").unwrap()
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
        ProjectPage::new(size, principal(), vec![project_snapshot(1); 3], None),
        Err(ProjectWorkspaceHostError::InvariantViolation)
    );
    assert_eq!(
        ProjectPage::new(
            size,
            principal(),
            vec![project_snapshot(1), project_snapshot(2)],
            Some(project_id(1)),
        ),
        Err(ProjectWorkspaceHostError::InvariantViolation)
    );
    let projects = ProjectPage::new(
        size,
        principal(),
        vec![project_snapshot(1), project_snapshot(2)],
        Some(project_id(2)),
    )
    .unwrap();
    assert_eq!(projects.items().len(), 2);

    let project = project_id(1);
    assert_eq!(
        WorkspacePage::new(
            size,
            principal(),
            project,
            vec![workspace_snapshot(1); 3],
            None
        ),
        Err(ProjectWorkspaceHostError::InvariantViolation)
    );
    assert_eq!(
        WorkspacePage::new(
            size,
            principal(),
            project,
            vec![workspace_snapshot(1), workspace_snapshot(2)],
            Some(workspace_id(1)),
        ),
        Err(ProjectWorkspaceHostError::InvariantViolation)
    );
    let workspaces = WorkspacePage::new(
        size,
        principal(),
        project,
        vec![workspace_snapshot(1), workspace_snapshot(2)],
        Some(workspace_id(2)),
    )
    .unwrap();
    assert_eq!(workspaces.items().len(), 2);
}

#[test]
fn continuation_tokens_are_versioned_canonical_and_principal_bound() {
    let owner = principal();
    let project_cursor = ProjectPageCursor::new(owner.clone(), project_id(2)).unwrap();
    let project_token = project_cursor.encode_token();
    assert_eq!(
        project_token.len(),
        gocode_api::PROJECT_PAGE_CURSOR_TOKEN_LENGTH
    );
    let other_length_token = ProjectPageCursor::new(
        ApiPrincipalId::new("a-principal-with-a-meaningfully-different-length").unwrap(),
        project_id(2),
    )
    .unwrap()
    .encode_token();
    assert_eq!(project_token.len(), other_length_token.len());
    assert!(!project_token.contains(owner.as_str()));
    assert_eq!(
        ProjectPageCursor::decode_token(&project_token),
        Ok(project_cursor)
    );
    let project_request = ProjectPageRequest::from_token(2, Some(&project_token)).unwrap();
    assert_eq!(
        project_request.parts_for_principal(&owner).unwrap().1,
        Some(project_id(2))
    );
    assert_eq!(
        project_request.parts_for_principal(&ApiPrincipalId::new("other").unwrap()),
        Err(ProjectWorkspaceHostError::NotFound)
    );

    let workspace_cursor =
        WorkspacePageCursor::new(owner.clone(), project_id(2), workspace_id(3)).unwrap();
    let workspace_token = workspace_cursor.encode_token();
    assert_eq!(
        workspace_token.len(),
        gocode_api::WORKSPACE_PAGE_CURSOR_TOKEN_LENGTH
    );
    assert_eq!(
        WorkspacePageCursor::decode_token(&workspace_token),
        Ok(workspace_cursor)
    );
    let workspace_request = WorkspacePageRequest::from_token(2, Some(&workspace_token)).unwrap();
    assert_eq!(
        workspace_request
            .parts_for_principal(&owner, project_id(2))
            .unwrap()
            .1,
        Some(workspace_id(3))
    );
    assert_eq!(
        workspace_request.parts_for_principal(&owner, project_id(4)),
        Err(ProjectWorkspaceHostError::NotFound)
    );
    assert_eq!(
        workspace_request
            .parts_for_principal(&ApiPrincipalId::new("other").unwrap(), project_id(2)),
        Err(ProjectWorkspaceHostError::NotFound)
    );

    let mut uppercase = project_token.clone();
    uppercase.replace_range(uppercase.len() - 1.., "A");
    let mut invalid_uuid = project_token.clone();
    invalid_uuid.replace_range(invalid_uuid.len() - 32.., &"00".repeat(16));
    let truncated = &project_token[..project_token.len() - 2];
    let oversized = format!("{project_token}00");
    let unknown_version = project_token.replacen("v1.", "v2.", 1);
    for invalid in [
        &unknown_version,
        truncated,
        &oversized,
        &uppercase,
        &invalid_uuid,
    ] {
        assert_eq!(
            ProjectPageCursor::decode_token(invalid),
            Err(PageCursorTokenError::Invalid)
        );
        assert_eq!(
            ProjectPageRequest::from_token(2, Some(invalid)),
            Err(ProjectWorkspaceHostError::NotFound)
        );
    }
}
