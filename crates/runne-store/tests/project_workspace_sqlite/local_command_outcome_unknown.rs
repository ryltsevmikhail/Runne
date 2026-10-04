#![cfg(target_os = "linux")]

use super::support::*;
use runne_api::{
    LocalCommandOutcomeV1, LocalCommandStopV1, RemoteEffectOutcomeV1, SuccessorEligibilityV1,
};
use runne_application::ports::{EventStore, ExecutionNodeId};
use runne_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use runne_store::store::LocalCommandAttemptState;

#[path = "local_command_outcome_unknown/fixture.rs"]
mod fixture;

#[test]
fn restart_with_empty_area_records_unknown_without_exit_or_relaunch() {
    eprintln!("RUN: local command restart empty-area unknown settlement");
    let fixture = fixture::prepare();
    let fixture::PreparedUnknown {
        database,
        taskrun_id,
        node,
        candidate,
        area,
        area_bytes,
        assignment,
        recovery_epoch,
        recovery_store,
    } = fixture;
    let connection = database.connection();

    assert!(
        recovery_store
            .settle_local_command_outcome_unknown_recovery(
                &candidate,
                &ExecutionNodeId(node.clone()),
                candidate.identity.node_epoch,
                area.prove_empty().unwrap(),
            )
            .is_err(),
        "the old epoch cannot settle its own attempt"
    );
    let empty = area.prove_empty().unwrap();
    recovery_store
        .settle_local_command_outcome_unknown_recovery(
            &candidate,
            &ExecutionNodeId(node.clone()),
            recovery_epoch,
            empty,
        )
        .expect("fresh node epoch commits unknown outcome and empty proof");
    let (replay_node, replay_epoch) = super::claim::node_registration(&database);
    assert_eq!(replay_node, node);
    assert!(replay_epoch > recovery_epoch);
    recovery_store
        .settle_local_command_outcome_unknown_recovery(
            &candidate,
            &ExecutionNodeId(replay_node.clone()),
            replay_epoch,
            area.prove_empty().unwrap(),
        )
        .expect("exact durable receipt replays after a later epoch without rewrite");

    let terminal = recovery_store.load_task_run(taskrun_id).unwrap();
    let task = TaskRun::replay(&terminal.events).unwrap();
    assert_eq!(task.state(), TaskRunState::Unrecoverable);
    assert!(matches!(
        terminal.events.last().unwrap().payload(),
        TaskRunEvent::Unrecoverable
    ));
    assert_eq!(terminal.current_version, 6);
    let effects = recovery_store
        .load_task_run_effects(taskrun_id)
        .expect("read effects from one committed snapshot");
    assert_eq!(effects.stream_version, terminal.current_version);
    assert_eq!(effects.attempt_id, Some(candidate.identity.attempt_id));
    assert!(!effects.cancellation_requested);
    let local = effects
        .local_command
        .expect("typed local effect is present");
    assert_eq!(local.outcome, LocalCommandOutcomeV1::OutcomeUnknown);
    assert_eq!(local.stop, LocalCommandStopV1::Confirmed);
    assert_eq!(
        local.exit_code, None,
        "unknown outcome never fabricates an exit"
    );
    assert_eq!(effects.remote.outcome, RemoteEffectOutcomeV1::NotApplicable);
    assert_eq!(effects.successor, SuccessorEligibilityV1::NotApplicable);
    let (attempt_state, exit): (String, Option<i32>) = connection
        .query_row(
            "SELECT state,exit_code FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(attempt_state, "outcome_unknown");
    assert_eq!(exit, None);
    assert_eq!(
        connection
            .query_row(
                "SELECT proof_node_epoch FROM taskrun_local_command_stop_receipts WHERE taskrun_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        recovery_epoch as i64,
        "replay retains the epoch that issued the original empty proof"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM taskrun_local_command_stop_receipts WHERE taskrun_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "released"
    );
    let unresolved_history = recovery_store
        .scan_local_command_recovery(None, 8)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.identity.taskrun_id == taskrun_id)
        .expect("unknown outcome remains auditable after its stop receipt");
    assert_eq!(
        unresolved_history.state,
        LocalCommandAttemptState::OutcomeUnknown
    );
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        runne_application::ports::RuntimeAuthorityId(node),
        guard(),
    )
    .expect("managed readiness accepts only the exact unknown stop receipt");
    assert_eq!(
        TaskRun::replay(&reopened.load_task_run(taskrun_id).unwrap().events)
            .unwrap()
            .state(),
        TaskRunState::Unrecoverable
    );
    let retained = recovery_store
        .scan_local_command_recovery(None, 8)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.identity.taskrun_id == taskrun_id)
        .expect("durable unknown fact stays available to cleanup recovery");
    // Model a crash after the unknown/empty proof and occupation receipt
    // committed but before the daemon removed the now-empty area. Recovery
    // must reopen the same inode and validate the exact receipt again first.
    let cleanup_root =
        runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup()
            .expect("current delegated root for cleanup recovery");
    let cleanup_area = cleanup_root
        .reopen_area(
            runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(&area_bytes)
                .unwrap(),
            runne_platform::process_managed_area::ManagedAreaBinding::new(
                *taskrun_id.as_bytes(),
                *assignment.attempt_id.as_bytes(),
                [0x82; 16],
            )
            .unwrap(),
        )
        .expect("reopen the exact retained area after receipt commit");
    recovery_store
        .settle_local_command_outcome_unknown_recovery(
            &retained,
            &ExecutionNodeId(replay_node.clone()),
            replay_epoch,
            cleanup_area.prove_empty().unwrap(),
        )
        .expect("post-commit recovery validates the saved proof without another event");
    cleanup_area.remove_empty().unwrap();
    recovery_store
        .mark_local_command_recovery_unconfirmed(
            &retained,
            &ExecutionNodeId(replay_node),
            replay_epoch,
        )
        .expect("cleanup replay cannot downgrade a proven unknown outcome");
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "outcome_unknown"
    );
    eprintln!("PASS: local command restart empty-area unknown settlement");
}
