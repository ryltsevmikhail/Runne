#![cfg(target_os = "linux")]

use super::support::*;
use runne_application::commands::CompleteTaskRunInput;
use runne_application::ports::EventStore;
use runne_domain::command::TerminalResult;
use runne_domain::task_run::TaskRunEvent;
use runne_store::store::LocalCommandAttemptState;

#[tokio::test(flavor = "current_thread")]
async fn terminal_event_must_match_durable_local_exit_code() {
    let prepared = super::legacy_local_command_fixture::prepare(
        "local-command-terminal-exit-guard",
        0x71,
        0x7c,
        [3; 32],
        [4; 32],
    )
    .await;
    let database = prepared.database;
    let taskrun_id = prepared.taskrun_id;
    let approval_binding = prepared.binding;
    let assignment = super::execution_input::claim(&database, taskrun_id, 0x73);
    let stream_version = database
        .store
        .load_task_run(taskrun_id)
        .unwrap()
        .current_version;
    assert_eq!(stream_version, 4);
    let managed_root =
        runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup()
            .expect("delegated Linux cgroup-v2 root");
    let area_binding = runne_platform::process_managed_area::ManagedAreaBinding::new(
        *taskrun_id.as_bytes(),
        *assignment.attempt_id.as_bytes(),
        [0x72; 16],
    )
    .expect("valid area binding");
    let managed_area = managed_root
        .create_area(area_binding)
        .expect("private attempt area");
    let area = managed_area.identity().to_bytes();
    database
        .store
        .bind_local_command_approval(
            taskrun_id,
            approval_binding,
            LocalCommandAttemptState::Approved,
        )
        .unwrap();
    database
        .store
        .persist_local_command_launch_intent(&assignment, stream_version, &area)
        .unwrap();
    let connection = database.connection();
    connection
        .execute(
            "UPDATE taskrun_local_command_attempts SET state='release_reserved' WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE taskrun_local_command_attempts SET state='running' WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    database
        .store
        .record_local_command_exit(&assignment, &area, 7, managed_area.prove_empty().unwrap())
        .unwrap();
    let complete = |result| CompleteTaskRunInput {
        taskrun_id,
        result,
        expected_version: stream_version,
    };
    assert!(
        database
            .task_runs()
            .complete_task_run(
                &task_context(0x74, "local-terminal-fake-success"),
                complete(TerminalResult::Success),
            )
            .is_err()
    );
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        stream_version,
        "a mismatched terminal result must not append an event"
    );
    database
        .task_runs()
        .complete_task_run(
            &task_context(0x75, "local-terminal-correct-failure"),
            complete(TerminalResult::Failure {
                reason: "local_command_exit_7".into(),
            }),
        )
        .unwrap();
    let terminal = database.store.load_task_run(taskrun_id).unwrap();
    let terminal_event = terminal.last_event_id.expect("terminal event identity");
    assert!(matches!(
        terminal.events.last().unwrap().payload(),
        TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Failure { .. }
        }
    ));
    database
        .store
        .settle_local_command_terminal(
            &assignment,
            &area,
            terminal_event,
            terminal.current_version,
            managed_area.prove_empty().unwrap(),
        )
        .unwrap();
    database
        .store
        .settle_local_command_terminal(
            &assignment,
            &area,
            terminal_event,
            terminal.current_version,
            managed_area.prove_empty().unwrap(),
        )
        .expect("exact terminal settlement replays idempotently");
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    assert_eq!(
        reopened.load_task_run(taskrun_id).unwrap().current_version,
        terminal.current_version,
        "the exact local terminal receipt survives managed reopen"
    );
    let connection = database.connection();
    let (state, event): (String, Vec<u8>) = connection
        .query_row(
            "SELECT state,release_event_id FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), assignment.fence.0],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "released");
    assert_eq!(event, terminal_event.as_bytes());
    assert!(
        database
            .store
            .scan_local_command_recovery(None, 128)
            .unwrap()
            .is_empty(),
        "a terminal receipt prevents settled work from reopening removed areas"
    );
    let cleanup = database
        .store
        .scan_local_command_terminal_cleanup(None, 128)
        .unwrap();
    assert_eq!(
        cleanup.len(),
        1,
        "durable terminal receipt schedules cleanup"
    );
    assert_eq!(cleanup[0].identity, assignment);
    assert_eq!(cleanup[0].area_identity, area);
    let identity =
        runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(&area).unwrap();
    assert!(
        managed_root
            .remove_area_if_present(identity.clone())
            .expect("crash-window cleanup proves and removes exact empty area")
    );
    assert!(
        !managed_root
            .remove_area_if_present(identity)
            .expect("replay after cleanup is idempotent")
    );
}
