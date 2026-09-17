use runne_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error,
};
use runne_domain::{id::ProjectId, project_workspace::ProjectWorkspaceDisplayName};

use super::support::*;

#[test]
fn rename_persists_the_name_and_version_and_replays_only_the_same_command() {
    let database = Database::new("project-workspace-rename");
    let repository = database.repository();
    create_project(&repository);
    let name = ProjectWorkspaceDisplayName::new("Renamed".into()).unwrap();
    let first = repository
        .rename_project(
            "owner",
            command(8),
            &key("rename-project"),
            ProjectId::from_bytes(PROJECT),
            1,
            name.clone(),
        )
        .unwrap();
    let replay = repository
        .rename_project(
            "owner",
            command(8),
            &key("rename-project"),
            ProjectId::from_bytes(PROJECT),
            1,
            name,
        )
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.display_name(), "Renamed");
    assert_eq!(first.version(), 2);
    assert_eq!(
        repository.rename_project(
            "owner",
            command(9),
            &key("rename-stale"),
            ProjectId::from_bytes(PROJECT),
            1,
            ProjectWorkspaceDisplayName::new("Again".into()).unwrap()
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        repository
            .get_project("owner", ProjectId::from_bytes(PROJECT))
            .unwrap(),
        first
    );
}

#[test]
fn project_row_rejects_an_impossible_initial_archived_state() {
    let database = Database::new("project-workspace-invalid-initial-archive");
    let repository = database.repository();
    create_project(&repository);
    database
        .connection()
        .execute(
            "UPDATE projects SET archived = 1 WHERE project_id = ?1",
            [PROJECT],
        )
        .unwrap();
    assert_eq!(
        repository.get_project("owner", ProjectId::from_bytes(PROJECT)),
        Err(Error::InvariantViolation)
    );
}
