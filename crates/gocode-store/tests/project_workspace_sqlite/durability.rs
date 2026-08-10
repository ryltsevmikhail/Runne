use gocode_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error,
};
use gocode_domain::id::{ProjectId, WorkspaceId};
use gocode_store::codec::{
    ProjectWorkspaceReceipt, ProjectWorkspaceReceiptCodec, StoreCodec, StoreCodecError,
};

use super::support::*;

#[test]
fn exact_receipt_and_state_survive_reopen() {
    let database = Database::new("project-workspace-reopen");
    let repository = database.repository();
    let created = create_project(&repository);
    drop(repository);

    let reopened = database.reopen();
    let replay = reopened
        .create_project(
            "owner",
            command(1),
            &key("create-project"),
            project(PROJECT, "One"),
        )
        .unwrap();

    assert_eq!(replay, created);
    assert_eq!(
        reopened
            .get_project("owner", ProjectId::from_bytes(PROJECT))
            .unwrap(),
        created
    );
}

#[test]
fn create_rejects_noninitial_aggregate_state_without_a_receipt() {
    let database = Database::new("project-workspace-noninitial-create");
    let repository = database.repository();
    let mut changed_project = project(PROJECT, "One");
    changed_project.archive().unwrap();
    assert_eq!(
        repository.create_project("owner", command(1), &key("create-project"), changed_project,),
        Err(Error::Conflict)
    );
    assert!(create_project(&repository).version() == 1);

    let mut changed_workspace = workspace(WORKSPACE, PROJECT, "Workspace");
    changed_workspace.open().unwrap();
    assert_eq!(
        repository.create_workspace(
            "owner",
            command(2),
            &key("create-workspace"),
            changed_workspace,
        ),
        Err(Error::Conflict)
    );
    assert!(create_workspace(&repository).version() == 1);
}

#[test]
fn receipt_collides_on_any_changed_command_semantics() {
    let database = Database::new("project-workspace-collisions");
    let repository = database.repository();
    create_project(&repository);

    let cases = [
        repository.create_project(
            "owner",
            command(1),
            &key("changed-key"),
            project(PROJECT, "One"),
        ),
        repository.create_project(
            "owner",
            command(1),
            &key("create-project"),
            project(PROJECT, "Changed name"),
        ),
        repository.create_project(
            "other",
            command(1),
            &key("create-project"),
            project(PROJECT, "One"),
        ),
        repository.create_project(
            "owner",
            command(1),
            &key("create-project"),
            project(PROJECT_2, "One"),
        ),
        repository.create_project(
            "owner",
            command(3),
            &key("create-project"),
            project(PROJECT, "One"),
        ),
        repository.archive_project(
            "owner",
            command(1),
            &key("create-project"),
            ProjectId::from_bytes(PROJECT),
            1,
        ),
    ];
    assert!(
        cases
            .into_iter()
            .all(|result| result == Err(Error::Conflict))
    );
    repository
        .archive_project(
            "owner",
            command(25),
            &key("archive-version"),
            ProjectId::from_bytes(PROJECT),
            1,
        )
        .unwrap();
    assert_eq!(
        repository.archive_project(
            "owner",
            command(25),
            &key("archive-version"),
            ProjectId::from_bytes(PROJECT),
            2,
        ),
        Err(Error::Conflict)
    );
}

#[test]
fn admission_digest_is_part_of_the_bind_receipt_fingerprint() {
    let database = Database::new("project-workspace-admission-digest");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let first = repository
        .bind_workspace_root(
            "owner",
            command(4),
            &key("bind-root"),
            WorkspaceId::from_bytes(WORKSPACE),
            1,
            &[0x41; 32],
        )
        .unwrap();
    assert_eq!(first.version(), 2);
    assert_eq!(
        repository.bind_workspace_root(
            "owner",
            command(4),
            &key("bind-root"),
            WorkspaceId::from_bytes(WORKSPACE),
            1,
            &[0x42; 32],
        ),
        Err(Error::Conflict)
    );
}

#[test]
fn queries_are_ordered_and_hide_foreign_existence() {
    let database = Database::new("project-workspace-queries");
    let repository = database.repository();
    repository
        .create_project(
            "owner",
            command(5),
            &key("second"),
            project(PROJECT_2, "Second"),
        )
        .unwrap();
    create_project(&repository);

    let ids = repository
        .list_projects("owner")
        .unwrap()
        .into_iter()
        .map(|value| value.id())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![
            ProjectId::from_bytes(PROJECT),
            ProjectId::from_bytes(PROJECT_2)
        ]
    );
    assert_eq!(
        repository.get_project("foreign", ProjectId::from_bytes(PROJECT)),
        Err(Error::NotFound)
    );
    assert_eq!(
        repository.get_project("foreign", ProjectId::from_bytes([0x77; 16])),
        Err(Error::NotFound)
    );
}

#[test]
fn project_workspace_receipt_codec_rejects_unknown_trailing_and_corrupt_bytes() {
    let codec = ProjectWorkspaceReceiptCodec;
    let encoded = codec
        .encode(&ProjectWorkspaceReceipt::Project(project(PROJECT, "One")))
        .unwrap();
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(matches!(
        codec.decode(&trailing),
        Err(StoreCodecError::TrailingBytes { remaining: 1 })
    ));
    let mut unknown = encoded.clone();
    unknown[2] = 0xff;
    assert!(matches!(
        codec.decode(&unknown),
        Err(StoreCodecError::UnknownTag { .. })
    ));
    let mut unsupported = encoded.clone();
    unsupported[1] = 2;
    assert!(matches!(
        codec.decode(&unsupported),
        Err(StoreCodecError::UnsupportedVersion { .. })
    ));
    let mut corrupt = encoded;
    corrupt[27] = 1;
    assert!(matches!(
        codec.decode(&corrupt),
        Err(StoreCodecError::InvalidValue { .. })
    ));
}
