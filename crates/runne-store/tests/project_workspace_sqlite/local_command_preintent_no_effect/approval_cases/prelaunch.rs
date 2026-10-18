use super::*;
use crate::project_workspace_sqlite::legacy_local_command_fixture;

#[tokio::test(flavor = "current_thread")]
async fn approved_unclaimed_cancel_reopens_with_bound_prelaunch_approval() {
    let prepared = legacy_local_command_fixture::prepare(
        "approved-preintent-cancel-reopen",
        0x81,
        0x84,
        [0x31; 32],
        [0x32; 32],
    )
    .await;
    let database = prepared.database;
    let taskrun_id = prepared.taskrun_id;
    let local = prepared.local;
    bind_approval(
        &database,
        taskrun_id,
        &local,
        prepared.binding,
        0x84,
        ApprovalDecision::Approve,
    )
    .await;
    let service = database.task_runs();
    service
        .cancel_task_run(
            &task_context(0x87, "approved-preintent-cancel"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    let completed = service
        .complete_queued_cancellation(
            &task_context(0x88, "approved-preintent-cancel-complete"),
            CompleteQueuedCancellationInput {
                taskrun_id,
                expected_version: 3,
            },
            &database.store,
        )
        .unwrap();
    assert!(matches!(
        completed,
        runne_application::ports::CompleteQueuedCancellationResult::Committed(_)
    ));
    assert_eq!(
        database
            .store
            .local_command_attempt_state(taskrun_id)
            .unwrap(),
        Some(LocalCommandAttemptState::NoEffectTerminal)
    );
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    let stream = reopened.load_task_run(taskrun_id).unwrap();
    assert_eq!(
        TaskRun::replay(&stream.events).unwrap().state(),
        TaskRunState::Cancelled
    );
    assert!(matches!(
        stream.events.last().unwrap().payload(),
        TaskRunEvent::CancellationCompleted
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn denied_prelaunch_approval_releases_once_and_reopens() {
    let prepared = legacy_local_command_fixture::prepare(
        "denied-preintent-reopen",
        0x91,
        0x94,
        [0x31; 32],
        [0x32; 32],
    )
    .await;
    let database = prepared.database;
    let taskrun_id = prepared.taskrun_id;
    let local = prepared.local;
    bind_approval(
        &database,
        taskrun_id,
        &local,
        prepared.binding,
        0x94,
        ApprovalDecision::Deny,
    )
    .await;
    assert!(
        crate::validated_reopen::reopen_store(
            database.file.path(),
            database.identity,
            authority(),
            guard(),
        )
        .is_ok(),
        "a bound legacy denial remains valid before claim"
    );
    let (node_id, epoch) = node_registration(&database);
    let claim = database
        .task_runs()
        .claim_task_run(
            &task_context(0x97, "denied-preintent-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch: epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &database.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(_) = claim else {
        panic!("fresh claim")
    };
    let (recovery_node, recovery_epoch) = node_registration(&database);
    assert_eq!(recovery_node, node_id);
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    let page = reopened
        .scan_no_effect_assignments(
            TaskRunNoEffectScanRequest::new(
                None,
                8,
                ExecutionNodeId(recovery_node),
                recovery_epoch,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(page.candidates.len(), 1);
    assert_eq!(page.candidates[0].identity.taskrun_id, taskrun_id);
    database
        .task_runs()
        .settle_taskrun_no_effect(
            &task_context(0x98, "denied-preintent-release"),
            page.candidates[0].clone(),
            &reopened,
        )
        .unwrap();
    let final_store = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    let stream = final_store.load_task_run(taskrun_id).unwrap();
    assert_eq!(
        TaskRun::replay(&stream.events).unwrap().state(),
        TaskRunState::Failed
    );
    assert!(
        matches!(stream.events.last().unwrap().payload(), TaskRunEvent::TaskRunFailed { reason } if reason == "dispatch_not_started")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn retained_denial_rejects_approval_whose_decision_is_approve() {
    let prepared = legacy_local_command_fixture::prepare(
        "denied-route-approved-approval",
        0x99,
        0x9a,
        [0x31; 32],
        [0x32; 32],
    )
    .await;
    let database = prepared.database;
    let taskrun_id = prepared.taskrun_id;
    bind_approval(
        &database,
        taskrun_id,
        &prepared.local,
        prepared.binding,
        0x9a,
        ApprovalDecision::Deny,
    )
    .await;
    database
        .connection()
        .execute(
            "UPDATE approvals SET state=2,decision=1 WHERE approval_id=?1",
            [prepared.approval_id.to_string()],
        )
        .unwrap();
    assert!(
        crate::validated_reopen::reopen_store(
            database.file.path(),
            database.identity,
            authority(),
            guard(),
        )
        .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn retained_denial_rejects_approval_for_another_principal() {
    let prepared = legacy_local_command_fixture::prepare(
        "denied-route-wrong-principal",
        0x9b,
        0x9c,
        [0x31; 32],
        [0x32; 32],
    )
    .await;
    let database = prepared.database;
    let taskrun_id = prepared.taskrun_id;
    bind_approval(
        &database,
        taskrun_id,
        &prepared.local,
        prepared.binding,
        0x9c,
        ApprovalDecision::Deny,
    )
    .await;
    database
        .connection()
        .execute(
            "UPDATE approvals SET principal_id='intruder' WHERE approval_id=?1",
            [prepared.approval_id.to_string()],
        )
        .unwrap();
    assert!(
        crate::validated_reopen::reopen_store(
            database.file.path(),
            database.identity,
            authority(),
            guard(),
        )
        .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn retained_no_effect_state_without_settlement_is_rejected() {
    let prepared = legacy_local_command_fixture::prepare(
        "no-effect-without-settlement",
        0x9d,
        0x9e,
        [0x31; 32],
        [0x32; 32],
    )
    .await;
    let database = prepared.database;
    database
        .connection()
        .execute(
            "UPDATE taskrun_local_command_attempts SET state='no_effect_terminal' WHERE taskrun_id=?1",
            [prepared.taskrun_id.as_bytes()],
        )
        .unwrap();
    assert!(
        crate::validated_reopen::reopen_store(
            database.file.path(),
            database.identity,
            authority(),
            guard(),
        )
        .is_err()
    );
}
