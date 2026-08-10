use gocode_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use gocode_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error,
};
use gocode_domain::command::TerminalResult;
use gocode_domain::id::{ConversationId, ProjectId, TaskRunId, WorkspaceId};

use super::support::*;

fn create_task_run(database: &Database, tail: u8) -> TaskRunId {
    let outcome = database
        .task_runs()
        .create_task_run(
            &task_context(tail, "task-create"),
            CreateTaskRunInput {
                conversation_id: ConversationId::from_bytes(command(0x31).into_bytes()),
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            },
        )
        .unwrap();
    match outcome {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn nonterminal_task_run_blocks_project_delete() {
    let database = Database::new("project-workspace-taskrun-fence");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    create_task_run(&database, 10);

    assert_eq!(
        repository.delete_project(
            "owner",
            command(11),
            &key("delete"),
            ProjectId::from_bytes(PROJECT),
            1,
        ),
        Err(Error::Conflict)
    );
}

#[test]
fn corrupt_task_run_relationship_fails_closed() {
    let database = Database::new("project-workspace-taskrun-corrupt");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let taskrun_id = create_task_run(&database, 12);
    database
        .connection()
        .execute(
            "UPDATE command_receipts SET idempotency_scope_bytes = x'0001'
             WHERE command_outcome IN (
               SELECT command_outcome FROM command_receipts WHERE command_id = ?1
             )",
            rusqlite::params![command(12).as_bytes()],
        )
        .unwrap();

    assert_ne!(taskrun_id, TaskRunId::from_bytes([0; 16]));
    assert_eq!(
        repository.delete_project(
            "owner",
            command(13),
            &key("delete-corrupt"),
            ProjectId::from_bytes(PROJECT),
            1,
        ),
        Err(Error::InvariantViolation)
    );
}

#[test]
fn terminal_task_run_allows_delete_only_without_live_workspace() {
    let database = Database::new("project-workspace-taskrun-terminal");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let taskrun_id = create_task_run(&database, 14);
    let service = database.task_runs();
    service
        .queue_task_run(
            &task_context(15, "queue"),
            QueueTaskRunInput {
                taskrun_id,
                expected_version: 1,
            },
        )
        .unwrap();
    service
        .admit_task_run(
            &task_context(16, "admit"),
            AdmitTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    service
        .start_attempt(
            &task_context(17, "start"),
            StartAttemptInput {
                taskrun_id,
                expected_version: 3,
            },
        )
        .unwrap();
    service
        .complete_task_run(
            &task_context(18, "complete"),
            CompleteTaskRunInput {
                taskrun_id,
                expected_version: 4,
                result: TerminalResult::Success,
            },
        )
        .unwrap();

    assert_eq!(
        repository.delete_project(
            "owner",
            command(19),
            &key("delete-live"),
            ProjectId::from_bytes(PROJECT),
            1,
        ),
        Err(Error::Conflict)
    );
    database
        .connection()
        .execute(
            "UPDATE workspaces SET live = 0 WHERE workspace_id = ?1",
            rusqlite::params![WORKSPACE],
        )
        .unwrap();
    assert_eq!(
        repository.delete_project(
            "owner",
            command(20),
            &key("delete-terminal"),
            ProjectId::from_bytes(PROJECT),
            1,
        ),
        Ok(2)
    );
}

#[test]
fn missing_task_run_stream_fails_closed() {
    let database = Database::new("project-workspace-taskrun-missing");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let taskrun_id = create_task_run(&database, 21);
    let connection = database.connection();
    connection
        .execute(
            "DELETE FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM aggregate_streams WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();

    assert_eq!(
        repository.delete_project(
            "owner",
            command(22),
            &key("delete-missing"),
            ProjectId::from_bytes(PROJECT),
            1,
        ),
        Err(Error::InvariantViolation)
    );
}

#[test]
fn command_id_is_globally_unique_across_project_and_taskrun_receipts() {
    let database = Database::new("pw-global-command-id");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    create_task_run(&database, 26);
    assert_eq!(
        repository.create_project(
            "owner",
            command(26),
            &key("cross-table-project"),
            project(PROJECT_2, "Two"),
        ),
        Err(Error::Conflict)
    );

    repository
        .create_project(
            "owner",
            command(27),
            &key("project-before-task"),
            project(PROJECT_2, "Two"),
        )
        .unwrap();
    let task_result = database.task_runs().create_task_run(
        &task_context(27, "task-after-project"),
        CreateTaskRunInput {
            conversation_id: ConversationId::from_bytes(command(0x33).into_bytes()),
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
        },
    );
    assert!(task_result.is_err());
}
