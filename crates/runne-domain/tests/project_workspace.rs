use runne_domain::{
    id::ProjectId,
    project_workspace::{
        MAX_PROJECT_WORKSPACE_DISPLAY_NAME_BYTES, ProjectWorkspaceDisplayName,
        ProjectWorkspaceError,
    },
};

#[test]
fn project_workspace_project_id_roundtrips_a_valid_uuid_v7() {
    let project_id = ProjectId::parse("018f47a2-4f8c-7b52-8c35-7a3a14c2d9e1").unwrap();

    assert_eq!(
        ProjectId::parse(&project_id.to_string()).unwrap(),
        project_id
    );
}

#[test]
fn display_names_reject_c0_c1_and_bidi_controls_but_allow_ordinary_unicode() {
    for value in [
        "bad\u{0000}",
        "bad\u{0085}",
        "bad\u{00ad}",
        "bad\u{061c}",
        "bad\u{202e}",
        "bad\u{2061}",
        "bad\u{2066}",
        "bad\u{e0001}",
    ] {
        assert_eq!(
            ProjectWorkspaceDisplayName::new(value.into()),
            Err(ProjectWorkspaceError::InvalidDisplayName)
        );
    }
    assert!(ProjectWorkspaceDisplayName::new("Проект café".into()).is_ok());
    assert_eq!(
        ProjectWorkspaceDisplayName::new("x".repeat(MAX_PROJECT_WORKSPACE_DISPLAY_NAME_BYTES + 1)),
        Err(ProjectWorkspaceError::InvalidDisplayName)
    );
}

#[test]
fn project_rename_is_versioned_and_rejects_noop_or_archived_projects() {
    let id = ProjectId::parse("018f47a2-4f8c-7b52-8c35-7a3a14c2d9e2").unwrap();
    let mut project = runne_domain::project_workspace::Project::create(
        id,
        ProjectWorkspaceDisplayName::new("One".into()).unwrap(),
    );
    project
        .rename(ProjectWorkspaceDisplayName::new("Two".into()).unwrap())
        .unwrap();
    assert_eq!(project.display_name(), "Two");
    assert_eq!(project.version(), 2);
    assert_eq!(
        project.rename(ProjectWorkspaceDisplayName::new("Two".into()).unwrap()),
        Err(ProjectWorkspaceError::InvalidTransition)
    );
    project.archive().unwrap();
    assert_eq!(
        project.rename(ProjectWorkspaceDisplayName::new("Three".into()).unwrap()),
        Err(ProjectWorkspaceError::InvalidTransition)
    );
    assert_eq!(
        runne_domain::project_workspace::Project::rehydrate(
            id,
            ProjectWorkspaceDisplayName::new("Archived".into()).unwrap(),
            1,
            true,
        ),
        Err(ProjectWorkspaceError::InvalidTransition)
    );
}
