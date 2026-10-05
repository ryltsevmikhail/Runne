use runne_application::{
    commands::{
        BeginClaimedConversationTextInput, BeginConversationTextInput, CommandOutcome,
        SubmitTaskRunInput,
    },
    conversation_service::ConversationService,
    conversation_text_service::ConversationTextCommandService,
    fingerprint::CommandFingerprint,
    ports::{
        AggregateScope, ApplicationCommandContext, IdempotencyScope, OperationTag,
        RuntimeAuthorityId, TaskRunAssignmentIdentity, TaskRunClaimResult, TextGenerationReceipt,
    },
    service::ClaimTaskRunInput,
};
use runne_domain::{
    id::{ConversationId, WorkspaceId},
    message::MessageText,
    task_run::{SelectedProviderProfile, TaskRunInput},
};
use runne_store::ProjectWorkspaceStore;

use super::super::support::{self, Database};

pub struct Fixture {
    pub database: Database,
    pub runtime_authority: RuntimeAuthorityId,
    pub taskrun_id: runne_domain::id::TaskRunId,
    pub conversation_id: ConversationId,
    pub assignment: TaskRunAssignmentIdentity,
    pub original: BeginConversationTextInput,
    pub generation_context: ApplicationCommandContext,
    pub started: TextGenerationReceipt,
    pub scope: IdempotencyScope,
    pub fingerprint: CommandFingerprint,
}

pub fn prepare(name: &str) -> Fixture {
    let runtime_authority = RuntimeAuthorityId("01010101010101010101010101010101".into());
    let database = Database::new_with_database_authority(name, runtime_authority.clone(), [1; 16]);
    let store = database.store.clone();
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    support::create_project(&repository);
    support::create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(support::command(0xf0).into_bytes());
    ConversationService::new(store.clone(), store.clone(), runtime_authority.clone())
        .create_from_application(
            &support::task_context(0xf0, "d2-cancel-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(support::WORKSPACE),
                command_id: support::command(0xf0),
                idempotency_key: support::key("d2-cancel-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let submitted = super::super::taskrun_tool_invocation_positive::loop_task_runs_for_authority(
        &store,
        runtime_authority.clone(),
    )
    .submit_task_run(
        &support::task_context(0xf1, "d2-cancel-submit"),
        SubmitTaskRunInput {
            conversation_id,
            workspace_id: WorkspaceId::from_bytes(support::WORKSPACE),
            input: TaskRunInput::new("safe cancellation fixture".into())
                .unwrap()
                .with_selected_profile(
                    SelectedProviderProfile::new("runne-linux-agent-tools-v1".into(), [2; 32])
                        .unwrap(),
                )
                .unwrap(),
        },
    )
    .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!("TaskRun submission expected")
    };
    let (node_id, node_epoch) = {
        let connection = database.connection();
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT authority_id FROM _authority WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let node = uuid::Uuid::from_bytes(bytes.try_into().unwrap()).to_string();
        let epoch = runne_store::schema::next_launch_generation(&connection).unwrap();
        runne_store::execution_node::register_local_linux_node(
            &connection,
            *uuid::Uuid::parse_str(&node).unwrap().as_bytes(),
            epoch,
            runne_store::execution_node::LinuxNodeDescriptor { capacity: 1 },
            300,
        )
        .unwrap();
        (node, epoch)
    };
    let task_runs = super::super::taskrun_tool_invocation_positive::loop_task_runs_for_authority(
        &store,
        runtime_authority.clone(),
    );
    let claim = task_runs
        .claim_task_run(
            &support::task_context(0xf2, "d2-cancel-claim"),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: runne_application::ports::ExecutionNodeId(node_id.clone()),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 300_000,
            },
            &store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!("TaskRun claim expected")
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: runne_application::ports::ExecutionNodeId(node_id),
        node_epoch,
        fence: claim.fence,
    };
    store
        .ensure_taskrun_tool_loop_budget(taskrun_id, claim.new_version, &assignment, 1)
        .unwrap();
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("safe cancellation fixture").unwrap(),
    };
    let generation_context = support::task_context(0xf3, "d2-cancel-generation");
    let started = runne_application::conversation_text_service::ConversationTextService::new(
        store.clone(),
        store.clone(),
        runtime_authority.clone(),
        support::guard(),
    )
    .begin_claimed_text(
        &generation_context,
        BeginClaimedConversationTextInput {
            original: original.clone(),
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id: WorkspaceId::from_bytes(support::WORKSPACE),
            assignment: assignment.clone(),
        },
    )
    .unwrap();
    let scope = IdempotencyScope {
        runtime_authority_id: runtime_authority.clone(),
        principal_id: generation_context.principal_id.clone(),
        operation: OperationTag::GenerateConversationText,
        aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
    };
    let fingerprint = CommandFingerprint::for_generate_conversation_text(
        &conversation_id,
        original.expected_version,
        &original.text,
    );
    Fixture {
        database,
        runtime_authority,
        taskrun_id,
        conversation_id,
        assignment,
        original,
        generation_context,
        started,
        scope,
        fingerprint,
    }
}
