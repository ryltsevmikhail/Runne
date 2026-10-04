use super::super::super::fixture::Harness;
use crate::canonical_provider::composition::tests::command_context;
use runne_api::CreateConversationInput;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, CancelTaskRunInput,
    CommandOutcome, SubmitTaskRunInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{ExecutionNodeId, RuntimeAuthorityId, TaskRunCancellationScanner};
use runne_application::service::TaskRunService;
use runne_domain::id::{ConversationId, TaskRunId, WorkspaceId};
use runne_domain::message::MessageText;
use runne_domain::task_run::TaskRunInput;
use std::sync::Arc;

#[path = "proof.rs"]
mod proof;
pub(super) use proof::provider_effect_counts;

pub(super) struct CancelledNoAdmission {
    pub(super) harness: Harness,
    pub(super) provider:
        Arc<crate::canonical_provider::composition::DaemonCanonicalProviderService>,
    pub(super) authority: RuntimeAuthorityId,
    pub(super) node_bytes: [u8; 16],
    pub(super) taskrun_id: TaskRunId,
    pub(super) conversation_id: ConversationId,
    pub(super) started: runne_application::ports::TextGenerationReceipt,
    pub(super) begin_context: runne_application::ports::ApplicationCommandContext,
    pub(super) cancellation_version: u64,
}

pub(super) async fn create_cancelled_no_admission(seed: u8) -> CancelledNoAdmission {
    let harness = Harness::new().await;
    let provider = harness.compose().await;
    let authority = RuntimeAuthorityId(hex::encode(provider.runtime_authority_id));
    let node_bytes = provider.runtime_authority_id;
    let workspace_id = "018f2e3a-7000-7000-8000-000000000093"
        .parse::<WorkspaceId>()
        .unwrap();
    let conversation_id = id(0x1c0 + u64::from(seed));
    let create_context = context(seed, 1, "no-admission-create");
    ConversationService::new(
        harness.store.clone(),
        harness.store.clone(),
        authority.clone(),
    )
    .create_from_application(
        &create_context,
        CreateConversationInput {
            conversation_id,
            workspace_id,
            command_id: create_context.command_id,
            idempotency_key: create_context.idempotency_key.clone(),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let tasks = TaskRunService::new(
        harness.store.clone(),
        harness.store.clone(),
        harness.store.clone(),
        authority.clone(),
    );
    let submit_context = context(seed, 2, "no-admission-submit");
    let submitted = tasks
        .submit_task_run(
            &submit_context,
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input: TaskRunInput::new("never admitted provider work".to_owned()).unwrap(),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!("TaskRun submission expected")
    };
    runne_store::execution_node::register_local_linux_node(
        &harness.writer_connection(),
        node_bytes,
        harness.generation(),
        runne_store::execution_node::LinuxNodeDescriptor { capacity: 1 },
        300,
    )
    .unwrap();
    let claim = tasks
        .claim_task_run(
            &context(seed, 3, "no-admission-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(uuid::Uuid::from_bytes(node_bytes).to_string()),
                node_epoch: harness.generation(),
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 300_000,
            },
            &harness.store,
        )
        .unwrap();
    let runne_application::ports::TaskRunClaimResult::Committed(claim) = claim else {
        panic!("TaskRun claim expected")
    };
    let text = harness.text_service();
    let begin_context = context(seed, 4, "no-admission-begin");
    let started = text
        .begin_claimed_text(
            &begin_context,
            BeginClaimedConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id,
                    expected_version: 1,
                    text: MessageText::new("never admitted provider work").unwrap(),
                },
                taskrun_id,
                attempt_id: claim.attempt_id,
                taskrun_version: claim.new_version,
                workspace_id,
                assignment: runne_application::ports::TaskRunAssignmentIdentity {
                    taskrun_id,
                    attempt_id: claim.attempt_id,
                    node_id: claim.node_id,
                    node_epoch: claim.node_epoch,
                    fence: claim.fence,
                },
            },
        )
        .unwrap();
    let cancelled = tasks
        .cancel_task_run(
            &context(seed, 5, "no-admission-cancel"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: started.taskrun_version,
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunCancellationRequested { new_version, .. } = cancelled else {
        panic!("TaskRun cancellation request expected")
    };
    assert!(
        harness
            .store
            .scan_pending_taskrun_cancellations(
                runne_application::ports::TaskRunQueueScanRequest::new(None, 8).unwrap()
            )
            .unwrap()
            .candidates
            .iter()
            .any(|candidate| candidate.taskrun_id == taskrun_id)
    );
    CancelledNoAdmission {
        harness,
        provider,
        authority,
        node_bytes,
        taskrun_id,
        conversation_id,
        started,
        begin_context,
        cancellation_version: new_version,
    }
}

fn context(seed: u8, step: u64, key: &str) -> runne_application::ports::ApplicationCommandContext {
    let suffix = 0x1d0 + u64::from(seed) * 8 + step;
    command_context(
        &format!("018f2e3a-7000-7000-8000-{suffix:012x}"),
        &format!("{key}-{seed}"),
    )
}

fn id(suffix: u64) -> ConversationId {
    format!("018f2e3a-7000-7000-8000-{suffix:012x}")
        .parse()
        .unwrap()
}
