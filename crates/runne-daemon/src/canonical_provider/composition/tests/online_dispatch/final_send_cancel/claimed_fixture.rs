use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, CommandOutcome,
    SubmitTaskRunInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunClaimResult};
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::id::WorkspaceId;
use runne_domain::message::MessageText;
use runne_domain::task_run::{SelectedProviderProfile, TaskRunInput};
use runne_runtime::canonical_provider_execution::CanonicalProviderExecutionJob;

use super::super::super::recovery_audit::Harness;
use super::test_context;

pub(super) fn claimed_job(
    harness: &Harness,
    service: &crate::canonical_provider::composition::DaemonCanonicalProviderService,
    selected: Option<SelectedProviderProfile>,
    suffix: u8,
) -> (CanonicalProviderExecutionJob, TaskRunAssignmentIdentity) {
    let authority = harness.authority();
    let conversation_id = uuid7(0x91, suffix);
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000093".parse().unwrap();
    let create_context = test_context(0xB0, suffix, "route-create");
    ConversationService::new(
        harness.store.clone(),
        harness.store.clone(),
        authority.clone(),
    )
    .create_from_application(
        &create_context,
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id,
            command_id: create_context.command_id,
            idempotency_key: create_context.idempotency_key.clone(),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let taskruns = TaskRunService::new(
        harness.store.clone(),
        harness.store.clone(),
        harness.store.clone(),
        authority,
    );
    let mut input = TaskRunInput::new("claimed route prompt".into()).unwrap();
    if let Some(selected) = &selected {
        input = input.with_selected_profile(selected.clone()).unwrap();
    }
    let taskrun_id = match taskruns
        .submit_task_run(
            &test_context(0xB1, suffix, "route-submit"),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input,
            },
        )
        .unwrap()
    {
        CommandOutcome::TaskRunSubmitted { taskrun_id, .. } => taskrun_id,
        other => panic!("unexpected submit outcome: {other:?}"),
    };
    let node = service.runtime_authority_id;
    runne_store::execution_node::register_local_linux_node(
        &harness.writer_connection(),
        node,
        harness.generation(),
        runne_store::execution_node::LinuxNodeDescriptor { capacity: 1 },
        300,
    )
    .unwrap();
    let claim = taskruns
        .claim_task_run(
            &test_context(0xB2, suffix, "route-claim"),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(uuid::Uuid::from_bytes(node).to_string()),
                node_epoch: harness.generation(),
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 300_000,
            },
            &harness.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!("TaskRun claim did not commit");
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: claim.node_id,
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("claimed route prompt").unwrap(),
    };
    let context = test_context(0xB3, suffix, "route-begin");
    let started = harness
        .text_service()
        .begin_claimed_text(
            &context,
            BeginClaimedConversationTextInput {
                original: original.clone(),
                taskrun_id,
                attempt_id: claim.attempt_id,
                taskrun_version: claim.new_version,
                workspace_id,
                assignment: assignment.clone(),
            },
        )
        .unwrap();
    (
        CanonicalProviderExecutionJob {
            context,
            original,
            started,
        },
        assignment,
    )
}

fn uuid7<T>(kind: u8, suffix: u8) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    format!("018f2e3a-7000-7000-8000-{kind:02x}{suffix:02x}00000001")
        .parse()
        .unwrap()
}
