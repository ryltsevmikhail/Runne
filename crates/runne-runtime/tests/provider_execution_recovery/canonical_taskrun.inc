fn seed_canonical_taskrun(
    database: &validated_reopen::ProviderTestDatabase,
) -> (ConversationId, TaskRunId, AttemptId) {
    use runne_application::commands::{
        BeginClaimedConversationTextInput, BeginConversationTextInput, CommandOutcome,
        SubmitTaskRunInput,
    };
    use runne_application::conversation_service::ConversationService;
    use runne_application::conversation_text_service::{
        ConversationTextCommandService, ConversationTextService,
    };
    use runne_application::ports::{
        ApplicationCommandContext, ExecutionNodeId, PrincipalId, RuntimeAuthorityId,
        TaskRunAssignmentIdentity, TaskRunClaimResult,
    };
    use runne_application::service::{ClaimTaskRunInput, TaskRunService};
    use runne_domain::event::Actor;
    use runne_domain::id::{IdempotencyKey, WorkspaceId};
    use runne_domain::message::MessageText;
    use runne_domain::task_run::{SelectedProviderProfile, TaskRunInput};
    use runne_store::execution_node::LinuxNodeDescriptor;
    use runne_store::store::StoreTransaction;
    use std::sync::Arc;

    fn command_context(byte: u8, key: &str) -> ApplicationCommandContext {
        ApplicationCommandContext {
            command_id: format!("018f2e3a-7000-7000-8000-0000000000{byte:02x}")
                .parse()
                .unwrap(),
            idempotency_key: IdempotencyKey::new(key).unwrap(),
            principal_id: PrincipalId("principal-1".to_owned()),
            actor: Actor::new("provider-runtime-recovery-fixture").unwrap(),
        }
    }

    let path = database.path();
    let writer = validated_reopen::open_validated_connection(path, database.identity()).unwrap();
    let reader = validated_reopen::open_validated_reader(path, database.identity()).unwrap();
    let runtime_authority = RuntimeAuthorityId(hex::encode([1; 16]));
    let store = StoreTransaction::open_with_connections(
        path,
        writer,
        reader,
        runtime_authority.clone(),
        Arc::new(AllowingGuard),
    )
    .unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-00000000000a".parse().unwrap();
    validated_reopen::seed_canonical_workspace(&store, "principal-1", workspace_id);
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-00000000000b".parse().unwrap();
    let create_context = command_context(0x11, "provider-runtime-create");
    ConversationService::new(store.clone(), store.clone(), runtime_authority.clone())
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
        store.clone(),
        store.clone(),
        store.clone(),
        runtime_authority.clone(),
    );
    let input = TaskRunInput::new("provider runtime recovery request".to_owned())
        .unwrap()
        .with_selected_profile(
            SelectedProviderProfile::new("fixture-profile-v1".to_owned(), [2; 32]).unwrap(),
        )
        .unwrap();
    let submitted = taskruns
        .submit_task_run(
            &command_context(0x12, "provider-runtime-submit"),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input,
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!("canonical fixture submission did not return a TaskRun")
    };

    let identity_connection = database.connection();
    let node_id: Vec<u8> = identity_connection
        .query_row(
            "SELECT authority_id FROM _authority WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let node_id: [u8; 16] = node_id.try_into().unwrap();
    let node_epoch = runne_store::schema::next_launch_generation(&identity_connection).unwrap();
    runne_store::execution_node::register_local_linux_node(
        &identity_connection,
        node_id,
        node_epoch,
        LinuxNodeDescriptor { capacity: 1 },
        300,
    )
    .unwrap();
    let claim_context = command_context(0x13, "provider-runtime-claim");
    let TaskRunClaimResult::Committed(claim) = taskruns
        .claim_task_run(
            &claim_context,
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId({
                    let encoded = hex::encode(node_id);
                    format!(
                        "{}-{}-{}-{}-{}",
                        &encoded[..8],
                        &encoded[8..12],
                        &encoded[12..16],
                        &encoded[16..20],
                        &encoded[20..]
                    )
                }),
                node_epoch,
                capability_descriptor: "linux-executor-v1".to_owned(),
                lease_duration_ms: 300_000,
            },
            &store,
        )
        .unwrap()
    else {
        panic!("canonical fixture claim did not commit")
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: claim.node_id,
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    ConversationTextService::new(
        store.clone(),
        store,
        runtime_authority,
        Arc::new(AllowingGuard),
    )
    .begin_claimed_text(
        &command_context(0x14, "provider-runtime-begin"),
        BeginClaimedConversationTextInput {
            original: BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("provider runtime recovery request").unwrap(),
            },
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id,
            assignment,
        },
    )
    .unwrap();
    (conversation_id, taskrun_id, claim.attempt_id)
}
