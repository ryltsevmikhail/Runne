use super::*;
use runne_api::{
    ApiActor, ApiPrincipalId, ApprovalCommandContext, ApprovalCommandHostPort,
    ApprovalCreateCommand, ApprovalDecision, ApprovalDecisionCommand, ApprovalRequestHostPort,
    ApprovalState,
};
use runne_application::commands::CancelTaskRunInput;
use runne_application::ports::{
    CompleteQueuedCancellationInput, EventStore, ExecutionNodeId, TaskRunClaimResult,
    TaskRunNoEffectScanRequest, TaskRunNoEffectScanner,
};
use runne_domain::id::{ApprovalId, InvocationId, TaskRunId};
use runne_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use runne_store::store::{LocalCommandApprovalBinding, LocalCommandAttemptState};

fn submitted_local(
    database: &Database,
    seed: u8,
) -> (TaskRunId, runne_domain::task_run::TaskRunLocalCommand) {
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(seed).into_bytes());
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(seed, "approved-preintent-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(seed),
                idempotency_key: key("approved-preintent-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let local = runne_domain::task_run::TaskRunLocalCommand::new(
        runne_domain::task_run::TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap();
    let outcome = database
        .task_runs()
        .submit_task_run(
            &task_context(seed + 1, "approved-preintent-submit"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: runne_domain::task_run::TaskRunInput::new("description".into())
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
    (taskrun_id, local)
}

async fn bind_approval(
    database: &Database,
    taskrun_id: TaskRunId,
    local: &runne_domain::task_run::TaskRunLocalCommand,
    tail: u8,
    decision: ApprovalDecision,
) -> ApprovalId {
    let approval_id = ApprovalId::from_bytes(command(tail).into_bytes());
    let digest = local.intent_digest();
    let request = ApprovalCreateCommand::new(
        approval_id,
        taskrun_id,
        None,
        InvocationId::from_bytes(command(tail + 1).into_bytes()),
        ApiPrincipalId::new("owner").unwrap(),
        "local_command.execute",
        "workspace",
        digest,
        2,
        1,
        i64::MAX,
        "reviewed local command",
    )
    .unwrap();
    let repository = database.repository();
    repository.create_pending_approval(request).await.unwrap();
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
            LocalCommandApprovalBinding {
                command_digest: digest,
                executable_digest: [0x31; 32],
                workspace_version: 1,
                admitted_root_version: 1,
                admitted_root_identity: [0x32; 32],
                trust_epoch: 1,
                trust_revision: 1,
                source_policy_version: 2,
                command_policy_version: 1,
                approval_id: *approval_id.as_bytes(),
            },
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
    let database = Database::new("approved-preintent-cancel-reopen");
    let (taskrun_id, local) = submitted_local(&database, 0x81);
    bind_approval(
        &database,
        taskrun_id,
        &local,
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
    let database = Database::new("denied-preintent-reopen");
    let (taskrun_id, local) = submitted_local(&database, 0x91);
    bind_approval(&database, taskrun_id, &local, 0x94, ApprovalDecision::Deny).await;
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
