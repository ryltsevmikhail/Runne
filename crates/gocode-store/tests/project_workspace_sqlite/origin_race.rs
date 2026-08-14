use std::sync::{Arc, Barrier};

use gocode_application::commands::CreateTaskRunInput;
use gocode_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error,
};
use gocode_domain::id::{ConversationId, ProjectId, WorkspaceId};

use super::support::*;

#[test]
fn live_workspace_serialization_commits_only_the_taskrun_origin() {
    let database = Database::new("pw-live-workspace-origin-race");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let (create, delete) = race_create_and_delete(&database, repository, 67, 68);

    assert!(create.is_ok());
    assert_eq!(delete, Err(Error::Conflict));
    assert_origin_counts(&database, command(67), (1, 1, true, true));
}

#[test]
fn tombstoned_workspace_serialization_commits_only_project_delete() {
    let database = Database::new("pw-tombstoned-workspace-origin-race");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    database
        .connection()
        .execute(
            "UPDATE workspaces SET live = 0 WHERE workspace_id = ?1",
            [WORKSPACE],
        )
        .unwrap();
    let (create, delete) = race_create_and_delete(&database, repository, 69, 70);

    assert!(create.is_err());
    assert_eq!(delete, Ok(4));
    assert_origin_counts(&database, command(69), (0, 0, false, false));
}

fn race_create_and_delete(
    database: &Database,
    repository: gocode_store::ProjectWorkspaceStore,
    create_tail: u8,
    delete_tail: u8,
) -> (
    Result<
        gocode_application::commands::CommandOutcome,
        gocode_application::errors::ApplicationError,
    >,
    Result<u64, Error>,
) {
    let task_runs = database.task_runs();
    let barrier = Arc::new(Barrier::new(3));
    let create_barrier = barrier.clone();
    let create = std::thread::spawn(move || {
        create_barrier.wait();
        task_runs.create_task_run(
            &task_context(create_tail, "racing-task-create"),
            CreateTaskRunInput {
                conversation_id: ConversationId::from_bytes(command(0x79).into_bytes()),
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            },
        )
    });
    let delete_barrier = barrier.clone();
    let delete = std::thread::spawn(move || {
        delete_barrier.wait();
        repository.delete_project(
            "owner",
            command(delete_tail),
            &key("racing-project-delete"),
            ProjectId::from_bytes(PROJECT),
            3,
        )
    });
    barrier.wait();
    (create.join().unwrap(), delete.join().unwrap())
}

fn assert_origin_counts(
    database: &Database,
    origin_command: gocode_domain::id::CommandId,
    expected: (i64, i64, bool, bool),
) {
    let connection = database.connection();
    let streams = connection
        .query_row(
            "SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let lineage = connection
        .query_row(
            "SELECT COUNT(*) FROM task_run_workspace_lineage",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let receipt = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM command_receipts WHERE command_id = ?1)",
            [origin_command.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let project = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE project_id = ?1)",
            [PROJECT],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((streams, lineage, receipt, project), expected);
}
