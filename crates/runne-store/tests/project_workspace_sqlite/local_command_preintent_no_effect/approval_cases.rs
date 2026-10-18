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

#[path = "approval_cases/prelaunch.rs"]
mod prelaunch;
#[path = "approval_cases/queued_cancel.rs"]
mod queued_cancel;
#[path = "approval_cases/route_guard.rs"]
mod route_guard;

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
