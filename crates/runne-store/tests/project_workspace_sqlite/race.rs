use std::sync::{Arc, Barrier};

use runne_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use runne_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error,
};
use runne_domain::command::TerminalResult;
use runne_domain::id::ProjectId;
use runne_domain::id::{ConversationId, WorkspaceId};

use super::support::*;

#[test]
fn concurrent_same_version_writers_commit_exactly_once() {
    let database = Database::new("project-workspace-race");
    let repository = database.repository();
    create_project(&repository);
    let barrier = Arc::new(Barrier::new(3));
    let threads = [
        (command(6), key("archive-a")),
        (command(7), key("archive-b")),
    ]
    .into_iter()
    .map(|(command_id, idempotency_key)| {
        let repository = repository.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let result = repository.archive_project(
                "owner",
                command_id,
                &idempotency_key,
                ProjectId::from_bytes(PROJECT),
                1,
            );
            (command_id, idempotency_key, result)
        })
    })
    .collect::<Vec<_>>();
    barrier.wait();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        results.iter().filter(|(_, _, value)| value.is_ok()).count(),
        1
    );
    let (failed_command, failed_key, _) = results
        .into_iter()
        .find(|(_, _, value)| *value == Err(Error::Conflict))
        .unwrap();
    repository
        .restore_project(
            "owner",
            command(8),
            &key("restore"),
            ProjectId::from_bytes(PROJECT),
            2,
        )
        .unwrap();
    let retried = repository
        .archive_project(
            "owner",
            failed_command,
            &failed_key,
            ProjectId::from_bytes(PROJECT),
            3,
        )
        .unwrap();
    assert_eq!(
        retried.version(),
        4,
        "failed writes must not persist receipts"
    );
}

#[test]
fn archive_and_workspace_create_share_the_parent_version_fence() {
    let database = Database::new("project-workspace-archive-create-fence");
    let repository = database.repository();
    create_project(&repository);
    let barrier = Arc::new(Barrier::new(3));
    let archive_repository = repository.clone();
    let create_repository = repository.clone();
    let archive_barrier = Arc::clone(&barrier);
    let create_barrier = Arc::clone(&barrier);
    let archive = std::thread::spawn(move || {
        archive_barrier.wait();
        archive_repository.archive_project(
            "owner",
            command(0x61),
            &key("archive-race"),
            ProjectId::from_bytes(PROJECT),
            1,
        )
    });
    let create = std::thread::spawn(move || {
        create_barrier.wait();
        create_repository.create_workspace(
            "owner",
            command(0x62),
            &key("create-race"),
            workspace(WORKSPACE, PROJECT, "Workspace"),
        )
    });
    barrier.wait();

    let archive = archive.join().unwrap();
    let create = create.join().unwrap();
    assert!(archive.is_ok() ^ create.is_ok());
}

#[test]
fn sqlite_abort_rolls_back_state_and_receipt_together() {
    let database = Database::new("project-workspace-rollback");
    let repository = database.repository();
    let connection = database.connection();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_project_insert BEFORE INSERT ON projects
             BEGIN SELECT RAISE(ABORT, 'simulated crash'); END;",
        )
        .unwrap();

    assert!(
        repository
            .create_project(
                "owner",
                command(9),
                &key("rollback"),
                project(PROJECT, "One")
            )
            .is_err()
    );
    connection
        .execute_batch("DROP TRIGGER reject_project_insert")
        .unwrap();
    let retry = repository
        .create_project(
            "owner",
            command(9),
            &key("rollback"),
            project(PROJECT, "One"),
        )
        .unwrap();
    assert_eq!(retry.version(), 1);
}

#[test]
fn project_delete_and_taskrun_append_share_one_sqlite_fence() {
    let database = Database::new("project-workspace-append-delete-fence");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let service = database.task_runs();
    let created = service
        .create_task_run(
            &task_context(28, "append-race-create"),
            CreateTaskRunInput {
                conversation_id: ConversationId::from_bytes(command(0x34).into_bytes()),
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            },
        )
        .unwrap();
    let taskrun_id = match created {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("unexpected outcome: {other:?}"),
    };
    service
        .queue_task_run(
            &task_context(29, "append-race-queue"),
            QueueTaskRunInput {
                taskrun_id,
                expected_version: 1,
            },
        )
        .unwrap();
    service
        .admit_task_run(
            &task_context(30, "append-race-admit"),
            AdmitTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    service
        .start_attempt(
            &task_context(31, "append-race-start"),
            StartAttemptInput {
                taskrun_id,
                expected_version: 3,
            },
        )
        .unwrap();
    database
        .connection()
        .execute(
            "UPDATE workspaces SET live = 0 WHERE workspace_id = ?1",
            [WORKSPACE],
        )
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let append_barrier = barrier.clone();
    let append = std::thread::spawn(move || {
        append_barrier.wait();
        service.complete_task_run(
            &task_context(32, "racing-task-append"),
            CompleteTaskRunInput {
                taskrun_id,
                expected_version: 4,
                result: TerminalResult::Success,
            },
        )
    });
    let delete_barrier = barrier.clone();
    let delete = std::thread::spawn(move || {
        delete_barrier.wait();
        repository.delete_project(
            "owner",
            command(33),
            &key("racing-delete-append"),
            ProjectId::from_bytes(PROJECT),
            2,
        )
    });
    barrier.wait();

    assert!(append.join().unwrap().is_ok());
    let deletion = delete.join().unwrap();
    assert!(matches!(deletion, Ok(4) | Err(Error::Conflict)));
}
