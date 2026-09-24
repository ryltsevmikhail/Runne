use runne_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, StartAttemptInput, SubmitTaskRunInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::EventStore;
use runne_application::ports::ProjectWorkspaceRepository;
use runne_domain::command::TerminalResult;
use runne_domain::event::Sensitivity;
use runne_domain::id::{ConversationId, ProjectId, WorkspaceId};

use super::support::*;

/// Submits one TaskRun bound to the canonical project workspace.
pub(super) fn submit_task_run(database: &Database, tail: u8, key_value: &str) -> CommandOutcome {
    let conversation_id = ConversationId::from_bytes(command(tail + 0x10).into_bytes());
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(tail + 0x20, &format!("{key_value}-conversation")),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(tail + 0x20),
                idempotency_key: key(&format!("{key_value}-conversation")),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    database
        .task_runs()
        .submit_task_run(
            &task_context(tail, key_value),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: runne_domain::task_run::TaskRunInput::new("test prompt".to_owned()).unwrap(),
            },
        )
        .unwrap()
}

#[test]
fn submit_persists_canonical_lineage_with_origin_20() {
    let database = Database::new("pw-submit-lineage");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x81, "submit-lineage");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submit must acknowledge TaskRunSubmitted");
    };

    let sensitivities = {
        let connection = database.connection();
        let mut statement = connection
            .prepare(
                "SELECT sequence, sensitivity FROM events
                 WHERE aggregate_type = 1 AND aggregate_id = ?1 ORDER BY sequence",
            )
            .unwrap();
        statement
            .query_map([taskrun_id.as_bytes()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert_eq!(sensitivities, [(1, 2), (2, 0)]);
    let loaded = database.store.load_task_run(taskrun_id).unwrap();
    assert_eq!(*loaded.events[0].sensitivity(), Sensitivity::Sensitive);
    assert_eq!(*loaded.events[1].sensitivity(), Sensitivity::Public);
    let replayed = runne_domain::task_run::TaskRun::replay(&loaded.events).unwrap();
    assert_eq!(
        replayed.state(),
        runne_domain::task_run::TaskRunState::Queued
    );

    let lineage = database
        .connection()
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
    assert_eq!(
        lineage.3, 20,
        "submit lineage must carry its own origin operation, not masquerade create"
    );
}

#[test]
fn submitted_task_run_blocks_project_delete() {
    let database = Database::new("pw-submit-fence");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    submit_task_run(&database, 0x83, "submit-fence");

    assert_eq!(
        repository.delete_project(
            "owner",
            command(0x84),
            &key("delete-submitted"),
            ProjectId::from_bytes(PROJECT),
            3,
        ),
        Err(runne_application::ports::ProjectWorkspaceRepositoryError::Conflict)
    );
}

#[test]
fn submit_duplicate_replays_the_stored_receipt_after_reopen() {
    let database = Database::new("pw-submit-duplicate");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let first = submit_task_run(&database, 0x85, "submit-duplicate");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = first else {
        panic!("first submit must acknowledge TaskRunSubmitted");
    };

    let replayed = database
        .reopened_task_runs()
        .submit_task_run(
            &task_context(0x85, "submit-duplicate"),
            SubmitTaskRunInput {
                conversation_id: ConversationId::from_bytes(command(0x95).into_bytes()),
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: runne_domain::task_run::TaskRunInput::new("test prompt".to_owned()).unwrap(),
            },
        )
        .unwrap();
    assert_eq!(replayed, first, "duplicate identity replays the stored ack");
    let events: i64 = database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(events, 2, "duplicate submit must not append events");
}

#[test]
fn submit_conflicting_payload_under_the_same_identity_conflicts_after_reopen() {
    let database = Database::new("pw-submit-conflict");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    submit_task_run(&database, 0x86, "submit-conflict");

    let error = database
        .reopened_task_runs()
        .submit_task_run(
            &task_context(0x86, "submit-conflict"),
            SubmitTaskRunInput {
                conversation_id: ConversationId::from_bytes(command(0xa6).into_bytes()),
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: runne_domain::task_run::TaskRunInput::new("changed prompt".to_owned())
                    .unwrap(),
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        runne_application::errors::ApplicationError::IdempotencyConflict { .. }
    ));
}

#[test]
fn terminal_submitted_task_run_still_respects_the_deletion_fence() {
    let database = Database::new("pw-submit-terminal");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let first = submit_task_run(&database, 0x87, "submit-terminal");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = first else {
        panic!("submit must acknowledge TaskRunSubmitted");
    };
    let service = database.task_runs();
    service
        .admit_task_run(
            &task_context(0x88, "admit-submitted"),
            AdmitTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    service
        .start_attempt(
            &task_context(0x89, "start-submitted"),
            StartAttemptInput {
                taskrun_id,
                expected_version: 3,
            },
        )
        .unwrap();
    service
        .complete_task_run(
            &task_context(0x8a, "complete-submitted"),
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
            command(0x8b),
            &key("delete-live-submitted"),
            ProjectId::from_bytes(PROJECT),
            3,
        ),
        Err(runne_application::ports::ProjectWorkspaceRepositoryError::Conflict)
    );
    database
        .connection()
        .execute(
            "UPDATE workspaces SET live = 0 WHERE workspace_id = ?1",
            [WORKSPACE.as_slice()],
        )
        .unwrap();
    assert_eq!(
        repository.delete_project(
            "owner",
            command(0x8c),
            &key("delete-terminal-submitted"),
            ProjectId::from_bytes(PROJECT),
            3,
        ),
        Ok(4)
    );
}
