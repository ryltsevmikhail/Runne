use runne_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use runne_application::errors::ApplicationError;
use runne_application::ports::{
    PrincipalId, ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error,
    StorageFailureKind,
};
use runne_domain::command::TerminalResult;
use runne_domain::id::{ConversationId, ProjectId, TaskRunId, WorkspaceId};

use super::support::*;

pub(super) fn create_task_run(database: &Database, tail: u8) -> TaskRunId {
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
            3,
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
            3,
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
            3,
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
            3,
        ),
        Ok(4)
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
            "DELETE FROM aggregate_state_snapshots WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
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
            3,
        ),
        Err(Error::InvariantViolation)
    );
}

#[test]
fn direct_taskrun_persists_canonical_workspace_lineage() {
    let database = Database::new("pw-direct-lineage");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let taskrun_id = create_task_run(&database, 34);

    let connection = database.connection();
    let lineage = connection
        .query_row(
            "SELECT workspace_id, project_id, classification, origin_operation
             FROM task_run_workspace_lineage WHERE taskrun_id = ?1",
            [taskrun_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(lineage.0, WORKSPACE);
    assert_eq!(lineage.1, Some(PROJECT.to_vec()));
    assert_eq!(lineage.2, "canonical");
    assert_eq!(lineage.3, 1);
}

#[test]
fn canonical_lineage_rejects_a_foreign_principal_origin() {
    let database = Database::new("pw-foreign-taskrun-origin");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let mut context = task_context(38, "foreign-task-create");
    context.principal_id = PrincipalId("intruder".into());

    let result = database.task_runs().create_task_run(
        &context,
        CreateTaskRunInput {
            conversation_id: ConversationId::from_bytes(command(0x32).into_bytes()),
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
        },
    );
    assert_eq!(
        result,
        Err(ApplicationError::StorageFailed(
            StorageFailureKind::IntegrityViolation
        ))
    );
}

#[test]
fn fresh_v16_rejects_unknown_workspace_without_partial_taskrun_origin() {
    let database = Database::new("pw-unknown-runtime-origin");
    let result = database.task_runs().create_task_run(
        &task_context(35, "unknown-task-create"),
        CreateTaskRunInput {
            conversation_id: ConversationId::from_bytes(command(0x33).into_bytes()),
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
        },
    );
    assert_eq!(
        result,
        Err(ApplicationError::StorageFailed(
            StorageFailureKind::IntegrityViolation
        ))
    );
    let connection = database.connection();
    for table in [
        "aggregate_streams",
        "events",
        "command_receipts",
        "task_run_workspace_lineage",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "unexpected partial write in {table}");
    }
}
