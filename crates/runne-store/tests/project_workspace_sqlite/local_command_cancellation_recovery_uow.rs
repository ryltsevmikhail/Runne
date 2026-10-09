#![cfg(target_os = "linux")]

#[path = "local_command_cancellation_recovery_uow/fixture.rs"]
mod fixture;
#[path = "local_command_cancellation_recovery_uow/stop_conflict.rs"]
mod stop_conflict;

use fixture::{attempt_row, reopen_recovery_candidate, scalar, taskrun_event_count};
use runne_application::ports::{EventStore, ExecutionNodeId};
use runne_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use runne_store::store::{LocalCommandAttemptState, LocalCommandCancellationStopEvidence};

use super::support::*;

#[tokio::test(flavor = "current_thread")]
async fn after_exit_split_completes_with_the_recorded_factual_exit() {
    let fixture = fixture::prepare_recovery_fixture(
        "cancel-uow-after-exit",
        0x71,
        true,
        "completed",
        Some(137),
    )
    .await;
    let (store, node_id, epoch, candidate) = reopen_recovery_candidate(&fixture);
    assert_eq!(candidate.state, LocalCommandAttemptState::Completed);
    assert_eq!(
        scalar(
            &fixture,
            "SELECT COUNT(*) FROM x2_permission_stop WHERE taskrun_id=?1"
        ),
        1,
        "cancel commit recorded the durable stop for a completed attempt"
    );
    store
        .complete_local_command_cancellation_recovery(
            &candidate,
            &ExecutionNodeId(node_id),
            epoch,
            fixture.area.prove_empty().unwrap(),
        )
        .unwrap();
    assert_eq!(attempt_row(&fixture), ("completed".into(), Some(137)));
    let loaded = store.load_task_run(fixture.taskrun_id).unwrap();
    assert_eq!(
        TaskRun::replay(&loaded.events).unwrap().state(),
        TaskRunState::Cancelled
    );
    assert!(matches!(
        loaded.events.last().unwrap().payload(),
        TaskRunEvent::CancellationCompleted
    ));
    assert_eq!(
        scalar(
            &fixture,
            "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1"
        ),
        1
    );
    assert_eq!(
        scalar(
            &fixture,
            "SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND state='released'"
        ),
        1
    );
    fixture::reopens_under_full_schema_validation(&fixture);
}

#[tokio::test(flavor = "current_thread")]
async fn missing_stop_proof_is_recorded_canonically_by_the_completion() {
    let fixture = fixture::prepare_recovery_fixture(
        "cancel-uow-missing-stop",
        0x72,
        true,
        "cancel_requested",
        None,
    )
    .await;
    let (store, node_id, epoch, candidate) = reopen_recovery_candidate(&fixture);
    assert_eq!(candidate.state, LocalCommandAttemptState::CancelRequested);
    assert_eq!(
        store
            .local_command_cancellation_stop_evidence(
                fixture.taskrun_id,
                candidate.identity.attempt_id
            )
            .unwrap(),
        LocalCommandCancellationStopEvidence::Recordable,
        "binding and CancellationRequested let recovery prove the stop itself"
    );
    store
        .complete_local_command_cancellation_recovery(
            &candidate,
            &ExecutionNodeId(node_id),
            epoch,
            fixture.area.prove_empty().unwrap(),
        )
        .unwrap();
    assert_eq!(attempt_row(&fixture), ("cancelled".into(), None));
    assert_eq!(
        scalar(
            &fixture,
            "SELECT COUNT(*) FROM x2_permission_stop WHERE taskrun_id=?1 AND reason=1"
        ),
        1,
        "completion recorded the canonical stop row"
    );
    assert!(
        store
            .load_task_run(fixture.taskrun_id)
            .unwrap()
            .events
            .last()
            .is_some_and(|event| matches!(event.payload(), TaskRunEvent::CancellationCompleted))
    );
    fixture::reopens_under_full_schema_validation(&fixture);
}

#[tokio::test(flavor = "current_thread")]
async fn completion_retry_is_inert_across_recovery_epochs() {
    let fixture = fixture::prepare_recovery_fixture(
        "cancel-uow-inert-retry",
        0x73,
        true,
        "cancel_requested",
        None,
    )
    .await;
    let (store, node_id, epoch, candidate) = reopen_recovery_candidate(&fixture);
    store
        .complete_local_command_cancellation_recovery(
            &candidate,
            &ExecutionNodeId(node_id.clone()),
            epoch,
            fixture.area.prove_empty().unwrap(),
        )
        .unwrap();
    let events_after_settlement = taskrun_event_count(&fixture);
    store
        .complete_local_command_cancellation_recovery(
            &candidate,
            &ExecutionNodeId(node_id.clone()),
            epoch,
            fixture.area.prove_empty().unwrap(),
        )
        .unwrap();
    assert_eq!(taskrun_event_count(&fixture), events_after_settlement);
    let (node_id_again, newer_epoch) = super::claim::node_registration(&fixture.database);
    assert_eq!(node_id_again, node_id);
    let reopened = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        runne_application::ports::RuntimeAuthorityId(node_id),
        guard(),
    )
    .unwrap();
    reopened
        .complete_local_command_cancellation_recovery(
            &candidate,
            &ExecutionNodeId(node_id_again),
            newer_epoch,
            fixture.area.prove_empty().unwrap(),
        )
        .unwrap();
    assert_eq!(taskrun_event_count(&fixture), events_after_settlement);
}

#[tokio::test(flavor = "current_thread")]
async fn denied_attempt_transition_rolls_back_without_terminal_artifacts() {
    let fixture = fixture::prepare_recovery_fixture(
        "cancel-uow-denied-update",
        0x74,
        true,
        "cancel_requested",
        None,
    )
    .await;
    let (store, node_id, epoch, candidate) = reopen_recovery_candidate(&fixture);
    fixture
        .database
        .connection()
        .execute(
            "CREATE TRIGGER deny_recovery_cancel BEFORE UPDATE ON taskrun_local_command_attempts
             WHEN NEW.state='cancelled' BEGIN SELECT RAISE(ABORT,'test denial'); END",
            [],
        )
        .unwrap();
    let events_before = taskrun_event_count(&fixture);
    assert!(
        store
            .complete_local_command_cancellation_recovery(
                &candidate,
                &ExecutionNodeId(node_id.clone()),
                epoch,
                fixture.area.prove_empty().unwrap(),
            )
            .is_err()
    );
    assert_eq!(taskrun_event_count(&fixture), events_before);
    assert_eq!(
        scalar(
            &fixture,
            "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1"
        ),
        0
    );
    assert_eq!(
        scalar(
            &fixture,
            "SELECT COUNT(*) FROM x2_permission_stop WHERE taskrun_id=?1"
        ),
        0,
        "the in-flight stop recording rolled back with the denied unit of work"
    );
    assert_eq!(
        scalar(
            &fixture,
            "SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND state='active'"
        ),
        1
    );
    assert_eq!(attempt_row(&fixture).0, "cancel_requested");
    fixture
        .database
        .connection()
        .execute("DROP TRIGGER deny_recovery_cancel", [])
        .unwrap();
    store
        .complete_local_command_cancellation_recovery(
            &candidate,
            &ExecutionNodeId(node_id),
            epoch,
            fixture.area.prove_empty().unwrap(),
        )
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_area_identity_candidate_is_rejected() {
    let fixture = fixture::prepare_recovery_fixture(
        "cancel-uow-wrong-identity",
        0x75,
        true,
        "cancel_requested",
        None,
    )
    .await;
    let (store, node_id, epoch, mut candidate) = reopen_recovery_candidate(&fixture);
    candidate.area_identity = vec![0_u8; 100];
    assert!(
        store
            .complete_local_command_cancellation_recovery(
                &candidate,
                &ExecutionNodeId(node_id),
                epoch,
                fixture.area.prove_empty().unwrap(),
            )
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn without_binding_the_stop_evidence_is_missing() {
    let fixture = fixture::prepare_recovery_fixture(
        "cancel-uow-no-binding",
        0x76,
        false,
        "cancel_requested",
        None,
    )
    .await;
    let (store, node_id, epoch, candidate) = reopen_recovery_candidate(&fixture);
    assert_eq!(
        store
            .local_command_cancellation_stop_evidence(
                fixture.taskrun_id,
                candidate.identity.attempt_id
            )
            .unwrap(),
        LocalCommandCancellationStopEvidence::Missing
    );
    assert!(
        store
            .complete_local_command_cancellation_recovery(
                &candidate,
                &ExecutionNodeId(node_id),
                epoch,
                fixture.area.prove_empty().unwrap(),
            )
            .is_err(),
        "corruption is not hidden: completion stays strict without the binding"
    );
    assert_eq!(attempt_row(&fixture).0, "cancel_requested");
}
