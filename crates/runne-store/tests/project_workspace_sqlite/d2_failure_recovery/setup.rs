use super::super::support::*;
use runne_application::{
    commands::{
        BeginClaimedConversationTextInput, BeginConversationTextInput, CommandOutcome,
        CommitContextInput, CommitPlanInput, CompleteLoopCycleInput, StartLoopCycleInput,
        SubmitTaskRunInput,
    },
    conversation_text_service::{ConversationTextCommandService, ConversationTextService},
    ports::{ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunClaimResult},
    service::ClaimTaskRunInput,
};
use runne_domain::{
    agent_loop::LoopDisposition,
    context::ContextManifestRef,
    id::{ContextManifestId, ConversationId, IntegrityDigest, PlanId, ResultId, WorkspaceId},
    message::MessageText,
    plan::PlanRevisionRef,
    reference::{BudgetReservationRef, ResultRef},
    task_run::TaskRunInput,
};
use runne_store::ProjectWorkspaceStore;
pub(super) struct Fixture {
    pub database: Database,
    pub runtime_authority: runne_application::ports::RuntimeAuthorityId,
    pub identity: crate::validated_reopen::MainDatabaseIdentity,
    pub store: runne_store::store::StoreTransaction,
    pub taskrun_id: runne_domain::id::TaskRunId,
    pub conversation_id: ConversationId,
    pub assignment: TaskRunAssignmentIdentity,
    pub original: BeginConversationTextInput,
    pub generation_context: runne_application::ports::ApplicationCommandContext,
    pub started: runne_application::ports::TextGenerationReceipt,
    pub cycle_id: runne_domain::id::CycleId,
}
pub(super) fn prepare() -> Fixture {
    prepare_with_cycle(true, "runne-linux-agent-tools-v1")
}
pub(super) fn prepare_before_cycle() -> Fixture {
    prepare_with_cycle(false, "runne-linux-agent-tools-v1")
}
fn prepare_with_cycle(with_cycle: bool, profile_id: &str) -> Fixture {
    let runtime_authority =
        runne_application::ports::RuntimeAuthorityId("01010101010101010101010101010101".into());
    let database = Database::new_with_database_authority(
        "d2-failure-recovery-gap",
        runtime_authority.clone(),
        [1; 16],
    );
    let store = database.store.clone();
    let identity = database.identity;
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0xd1).into_bytes());
    runne_application::conversation_service::ConversationService::new(
        store.clone(),
        store.clone(),
        runtime_authority.clone(),
    )
    .create_from_application(
        &task_context(0xd2, "d2-failure-conversation"),
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            command_id: command(0xd2),
            idempotency_key: key("d2-failure-conversation"),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let task_runs = super::super::taskrun_tool_invocation_positive::loop_task_runs_for_authority(
        &store,
        runtime_authority.clone(),
    );
    let submitted = task_runs
        .submit_task_run(
            &task_context(0xd3, "d2-failure-submit"),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: TaskRunInput::new("failure recovery candidate".into())
                    .unwrap()
                    .with_selected_profile(
                        runne_domain::task_run::SelectedProviderProfile::new(
                            profile_id.into(),
                            [2; 32],
                        )
                        .unwrap(),
                    )
                    .unwrap(),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!("TaskRun submit expected")
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
    let claim = task_runs
        .claim_task_run(
            &task_context(0xd4, "d2-failure-claim"),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
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
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        fence: claim.fence,
    };
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("failure recovery candidate").unwrap(),
    };
    let generation_context = task_context(0xe1, "d2-failure-generation");
    let started = ConversationTextService::new(
        store.clone(),
        store.clone(),
        runtime_authority.clone(),
        guard(),
    )
    .begin_claimed_text(
        &generation_context,
        BeginClaimedConversationTextInput {
            original: original.clone(),
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            assignment: assignment.clone(),
        },
    )
    .unwrap();
    if !with_cycle {
        return Fixture {
            database,
            runtime_authority,
            identity,
            store,
            taskrun_id,
            conversation_id,
            assignment,
            original,
            generation_context,
            started,
            cycle_id: runne_domain::id::CycleId::from_bytes([0x34; 16]),
        };
    }
    let cycle = task_runs
        .start_loop_cycle(
            &task_context(0xd5, "d2-failure-cycle"),
            StartLoopCycleInput {
                taskrun_id,
                expected_version: claim.new_version,
            },
        )
        .unwrap();
    let CommandOutcome::CycleStarted {
        cycle_id,
        new_version,
        ..
    } = cycle
    else {
        panic!("cycle start expected")
    };
    let budget = store
        .ensure_taskrun_tool_loop_budget(taskrun_id, new_version, &assignment, 1)
        .unwrap();
    let manifest = ContextManifestRef {
        manifest_id: ContextManifestId::from_bytes(command(0xd7).into_bytes()),
        taskrun_id,
        attempt_id: claim.attempt_id,
        cycle_id,
        revision: 1,
        policy_revision: "d2-test-context-v1".into(),
        integrity_digest: IntegrityDigest::from_bytes([0xd7; 32]),
    };
    let context = task_runs
        .commit_context(
            &task_context(0xd8, "d2-failure-context"),
            CommitContextInput {
                taskrun_id,
                expected_version: new_version,
                cycle_id,
                manifest_ref: manifest.clone(),
            },
        )
        .unwrap();
    let CommandOutcome::ContextCommitted { new_version, .. } = context else {
        panic!("context commit expected")
    };
    let plan = PlanRevisionRef {
        plan_id: PlanId::from_bytes(command(0xd9).into_bytes()),
        taskrun_id,
        cycle_id,
        revision: 1,
        context_manifest_ref: manifest,
        expected_proposal_indexes: vec![0, 1],
        proposal_batch_digest: IntegrityDigest::from_bytes([0xda; 32]),
        planning_policy_ref: ResultRef::new(
            ResultId::from_bytes(command(0xdb).into_bytes()),
            "application/vnd.runne.policy",
            IntegrityDigest::from_bytes([0xdc; 32]),
        )
        .unwrap(),
        planning_budget_ref: BudgetReservationRef {
            reservation_id: budget.reservation_id,
            taskrun_id,
            attempt_id: claim.attempt_id,
            retry_ordinal: 0,
            reservation_digest: budget.reservation_digest,
        },
        parent_ref: None,
        integrity_digest: IntegrityDigest::from_bytes([0xdd; 32]),
    };
    let committed_plan = task_runs
        .commit_plan(
            &task_context(0xde, "d2-failure-plan"),
            CommitPlanInput {
                taskrun_id,
                expected_version: new_version,
                cycle_id,
                plan_revision_ref: plan,
                input_digest: IntegrityDigest::from_bytes([0xdf; 32]),
                output_digest: IntegrityDigest::from_bytes([0xe0; 32]),
                expected_proposal_indexes: vec![0, 1],
            },
        )
        .unwrap();
    let CommandOutcome::PlanCommitted { new_version, .. } = committed_plan else {
        panic!("plan commit expected")
    };
    super::super::provider_binding::bind_d2_round_zero_for_test(
        &database,
        &assignment,
        conversation_id,
        claim.new_version,
        new_version,
    );
    task_runs
        .complete_loop_cycle(
            &task_context(0xd6, "d2-failure-terminal"),
            CompleteLoopCycleInput {
                taskrun_id,
                expected_version: new_version,
                cycle_id,
                disposition: LoopDisposition::Fail {
                    reason: "provider_execution_rejected".into(),
                    unresolved_proposals: vec![0, 1],
                },
            },
        )
        .unwrap();
    Fixture {
        database,
        runtime_authority,
        identity,
        store,
        taskrun_id,
        conversation_id,
        assignment,
        original,
        generation_context,
        started,
        cycle_id,
    }
}
