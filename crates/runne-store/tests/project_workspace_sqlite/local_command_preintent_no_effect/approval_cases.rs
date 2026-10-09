use super::*;
use runne_api::{
    ApiActor, ApiPrincipalId, ApprovalCommandContext, ApprovalCommandHostPort, ApprovalDecision,
    ApprovalDecisionCommand, ApprovalState,
};
use runne_application::commands::CancelTaskRunInput;
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{
    CompleteQueuedCancellationInput, EventStore, ExecutionNodeId, TaskRunClaimResult,
    TaskRunNoEffectScanRequest, TaskRunNoEffectScanner,
};
use runne_domain::id::{ApprovalId, ConversationId, TaskRunId, WorkspaceId};
use runne_domain::task_run::{
    TaskRun, TaskRunEvent, TaskRunExecutable, TaskRunInput, TaskRunLocalCommand, TaskRunState,
};
use runne_store::store::{LocalCommandApprovalBinding, LocalCommandAttemptState};

async fn bind_approval(
    database: &Database,
    taskrun_id: TaskRunId,
    local: &runne_domain::task_run::TaskRunLocalCommand,
    binding: LocalCommandApprovalBinding,
    tail: u8,
    decision: ApprovalDecision,
) -> ApprovalId {
    let approval_id = ApprovalId::from_bytes(command(tail).into_bytes());
    let digest = local.intent_digest();
    assert_eq!(binding.command_digest, digest);
    assert_eq!(binding.approval_id, *approval_id.as_bytes());
    let repository = database.repository();
    let approval = repository
        .decide_approval(
            ApprovalCommandContext {
                command_id: command(tail + 2),
                idempotency_key: key("approved-preintent-decision"),
                principal: ApiPrincipalId::new("owner").unwrap(),
                actor: ApiActor::new("desktop").unwrap(),
            },
            ApprovalDecisionCommand::new(approval_id, 1, decision, digest, 2, 1).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        approval.state(),
        match decision {
            ApprovalDecision::Approve => ApprovalState::Approved,
            ApprovalDecision::Deny => ApprovalState::Denied,
        }
    );
    database
        .store
        .bind_local_command_approval(
            taskrun_id,
            binding,
            match decision {
                ApprovalDecision::Approve => LocalCommandAttemptState::Approved,
                ApprovalDecision::Deny => LocalCommandAttemptState::Denied,
            },
        )
        .unwrap();
    approval_id
}

#[tokio::test(flavor = "current_thread")]
async fn approved_unclaimed_cancel_reopens_with_bound_prelaunch_approval() {
    let prepared = super::super::legacy_local_command_fixture::prepare(
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
    let prepared = super::super::legacy_local_command_fixture::prepare(
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
    let (node_id, epoch) = super::super::claim::node_registration(&database);
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
    let (recovery_node, recovery_epoch) = super::super::claim::node_registration(&database);
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
    let prepared = super::super::legacy_local_command_fixture::prepare(
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
    let prepared = super::super::legacy_local_command_fixture::prepare(
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
    let prepared = super::super::legacy_local_command_fixture::prepare(
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

async fn queued_cancel_fixture(name: &str, seed: u8) -> (Database, TaskRunId, Vec<u8>) {
    let prepared = super::super::legacy_local_command_fixture::prepare(
        name,
        seed,
        seed.wrapping_add(1),
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
        seed.wrapping_add(1),
        ApprovalDecision::Approve,
    )
    .await;
    database
        .task_runs()
        .cancel_task_run(
            &task_context(seed.wrapping_add(2), "queued-cancel-proof-negative"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    let result = database
        .task_runs()
        .complete_queued_cancellation(
            &task_context(
                seed.wrapping_add(4),
                "queued-cancel-proof-negative-complete",
            ),
            CompleteQueuedCancellationInput {
                taskrun_id,
                expected_version: 3,
            },
            &database.store,
        )
        .unwrap();
    assert!(matches!(
        result,
        runne_application::ports::CompleteQueuedCancellationResult::Committed(_)
    ));
    let command_id = database
        .connection()
        .query_row(
            "SELECT command_id FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=4",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    (database, taskrun_id, command_id)
}

#[tokio::test(flavor = "current_thread")]
async fn retained_queued_cancellation_rejects_missing_completion_receipt() {
    let (database, taskrun_id, command_id) =
        queued_cancel_fixture("queued-cancel-missing-receipt", 0xa1).await;
    database
        .connection()
        .execute(
            "DELETE FROM command_receipts WHERE command_id=?1",
            [command_id],
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
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        4
    );
}

#[tokio::test(flavor = "current_thread")]
async fn retained_queued_cancellation_rejects_mismatched_completion_receipt() {
    let (database, _, command_id) = queued_cancel_fixture("queued-cancel-bad-receipt", 0xa3).await;
    database
        .connection()
        .execute(
            "UPDATE command_receipts SET fingerprint=zeroblob(32) WHERE command_id=?1",
            [command_id],
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
async fn retained_queued_cancellation_rejects_claim_evidence() {
    let (database, taskrun_id, _) =
        queued_cancel_fixture("queued-cancel-claim-evidence", 0xa5).await;
    database
        .connection()
        .execute(
            "INSERT INTO taskrun_fence_counters(taskrun_id,last_fence) VALUES(?1,1)",
            [taskrun_id.as_bytes()],
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

#[test]
fn compiled_route_rejects_legacy_approval_binding() {
    let database = Database::new("compiled-route-rejects-legacy-binding");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0xb1).into_bytes());
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(0xb1, "compiled-route-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(0xb1),
                idempotency_key: key("compiled-route-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let local = TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap();
    let outcome = database
        .task_runs()
        .submit_task_run(
            &task_context(0xb2, "compiled-route-submit"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: TaskRunInput::new("description".into())
                    .unwrap()
                    .with_local_command(local.clone())
                    .unwrap(),
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome
    else {
        panic!("submitted local TaskRun")
    };
    let binding = LocalCommandApprovalBinding {
        command_digest: local.intent_digest(),
        executable_digest: [0x31; 32],
        workspace_version: 1,
        admitted_root_version: 1,
        admitted_root_identity: [0x32; 32],
        trust_epoch: 1,
        trust_revision: 1,
        source_policy_version: 2,
        command_policy_version: 1,
        approval_id: *ApprovalId::from_bytes(command(0xb3).into_bytes()).as_bytes(),
    };
    assert!(
        database
            .store
            .bind_local_command_approval(
                taskrun_id,
                binding,
                LocalCommandAttemptState::ApprovalPending,
            )
            .is_err()
    );
    let route: (i64, i64, i64) = database
        .connection()
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(route, (2, 3, 68));
}
