use runne_application::ports::EventStore;
use runne_application::provider::{ProviderEncryptedPayload, ProviderJournalKeyBinding};
use runne_application::{
    commands::{CommitContextInput, CommitPlanInput, StartLoopCycleInput},
    conversation_service::ConversationService,
    ports::{
        ExecutionNodeId, ReconciliationError, ReconciliationQueryPort, RetryScheduleError,
        RetrySchedulePort, TaskRunAssignmentIdentity, TaskRunClaimResult, TimeError, TimePort,
        VerificationQueryError, VerificationQueryPort, WakeEvidenceError, WakeEvidenceQueryPort,
    },
    service::{AgentLoopAuthorities, ClaimTaskRunInput, TaskRunService},
};
use runne_domain::{
    agent_loop::LoopCycleState,
    context::ContextManifestRef,
    id::{ContextManifestId, ConversationId, IntegrityDigest, PlanId, ResultId, WorkspaceId},
    plan::PlanRevisionRef,
    reference::{BudgetReservationRef, ResultRef},
    task_run::{TaskRun, TaskRunInput},
};
use runne_store::store::taskrun_tool_invocation::{
    EncryptedToolPayloadV1, ToolInvocationBindingV1, ToolInvocationKey, ToolInvocationStoreError,
    ToolSourceRef,
};
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};

use super::support::*;

#[test]
fn canonical_tool_invocation_fixture_reaches_committed_acting_plan() {
    let database =
        crate::validated_reopen::ProviderTestDatabase::new("tool-invocation-positive-plan");
    let (store, _) =
        crate::validated_reopen::initialize_store(database.path(), authority(), guard()).unwrap();
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0xc1).into_bytes());
    ConversationService::new(store.clone(), store.clone(), authority())
        .create_from_application(
            &task_context(0xc2, "tool-invocation-positive-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(0xc2),
                idempotency_key: key("tool-invocation-positive-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let submitted = TaskRunService::new(store.clone(), store.clone(), store.clone(), authority())
        .submit_task_run(
            &task_context(0xb1, "tool-invocation-positive"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: TaskRunInput::new("tool invocation fixture".into()).unwrap(),
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submitted
    else {
        panic!("canonical submit expected")
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
    let task_runs = loop_task_runs(&store);
    let claim = task_runs
        .claim_task_run(
            &task_context(0xb2, "tool-invocation-claim"),
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
        panic!("canonical task claim expected")
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        fence: claim.fence,
    };
    let budget = store
        .ensure_taskrun_tool_loop_budget(taskrun_id, claim.new_version, &assignment, 1)
        .unwrap();

    let cycle = match task_runs
        .start_loop_cycle(
            &task_context(0xb3, "tool-invocation-cycle"),
            StartLoopCycleInput {
                taskrun_id,
                expected_version: claim.new_version,
            },
        )
        .unwrap()
    {
        runne_application::commands::CommandOutcome::CycleStarted {
            cycle_id,
            new_version,
            ..
        } => (cycle_id, new_version),
        other => panic!("unexpected cycle result: {other:?}"),
    };
    let manifest = ContextManifestRef {
        manifest_id: ContextManifestId::from_bytes(command(0xb4).into_bytes()),
        taskrun_id,
        attempt_id: claim.attempt_id,
        cycle_id: cycle.0,
        revision: 1,
        policy_revision: "d2-test-context-v1".into(),
        integrity_digest: IntegrityDigest::from_bytes([0xb5; 32]),
    };
    let context = task_runs
        .commit_context(
            &task_context(0xb6, "tool-invocation-context"),
            CommitContextInput {
                taskrun_id,
                expected_version: cycle.1,
                cycle_id: cycle.0,
                manifest_ref: manifest.clone(),
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::ContextCommitted { new_version, .. } = context
    else {
        panic!("canonical context commit expected")
    };
    let plan_ref = PlanRevisionRef {
        plan_id: PlanId::from_bytes(command(0xb7).into_bytes()),
        taskrun_id,
        cycle_id: cycle.0,
        revision: 1,
        context_manifest_ref: manifest,
        expected_proposal_indexes: vec![0],
        proposal_batch_digest: IntegrityDigest::from_bytes([0xb8; 32]),
        planning_policy_ref: ResultRef::new(
            ResultId::from_bytes(command(0xb9).into_bytes()),
            "application/vnd.runne.policy",
            IntegrityDigest::from_bytes([0xba; 32]),
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
        integrity_digest: IntegrityDigest::from_bytes([0xbb; 32]),
    };
    task_runs
        .commit_plan(
            &task_context(0xbc, "tool-invocation-plan"),
            CommitPlanInput {
                taskrun_id,
                expected_version: new_version,
                cycle_id: cycle.0,
                plan_revision_ref: plan_ref,
                input_digest: IntegrityDigest::from_bytes([0xbd; 32]),
                output_digest: IntegrityDigest::from_bytes([0xbe; 32]),
                expected_proposal_indexes: vec![0],
            },
        )
        .unwrap();

    let stream = store.load_task_run(taskrun_id).unwrap();
    let task = TaskRun::replay(&stream.events).unwrap();
    let active = task.active_cycle().unwrap();
    assert_eq!(active.cycle_id, cycle.0);
    assert_eq!(active.attempt_id, claim.attempt_id);
    assert_eq!(active.state, LoopCycleState::Acting);
    assert_eq!(active.expected_proposal_indexes, [0]);
    assert_eq!(budget.taskrun_id, taskrun_id);

    let stale_version = stream.current_version;
    task_runs
        .cancel_task_run(
            &task_context(0xc3, "tool-invocation-cancel"),
            runne_application::commands::CancelTaskRunInput {
                taskrun_id,
                expected_version: stale_version,
            },
        )
        .unwrap();
    let mut binding = ToolInvocationBindingV1 {
        key: ToolInvocationKey {
            taskrun_id,
            attempt_id: claim.attempt_id,
            cycle_id: cycle.0,
            proposal_index: 0,
        },
        expected_taskrun_version: stale_version,
        call_id: "cancelled-call".into(),
        tool_name: "file.read".into(),
        tool_revision: "1".into(),
        schema_digest: IntegrityDigest::from_bytes([0xc4; 32]),
        canonical_arguments: br#"{"name":"file.txt"}"#.to_vec(),
        arguments_digest: IntegrityDigest::from_bytes([0; 32]),
        semantic_digest: IntegrityDigest::from_bytes([0; 32]),
        sources: vec![ToolSourceRef {
            dispatch_attempt_id: [0xc5; 16],
            sequence: 1,
            event_kind: 5,
            terminal: true,
            plaintext_digest: IntegrityDigest::from_bytes([0xc6; 32]),
            profile_digest: IntegrityDigest::from_bytes([0xc7; 32]),
            runtime_generation: 1,
        }],
        environment_id: "workspace".into(),
        environment_revision: "revision".into(),
        root_identity: IntegrityDigest::from_bytes([0xc8; 32]),
        root_revision: 1,
        target_name: "file.txt".into(),
        target_precondition: None,
        approval_id: [0xc9; 16],
        principal_id: "submitter".into(),
        approval_principal_id: "submitter".into(),
        approval_action: "file.read".into(),
        approval_resource: "workspace:file.txt".into(),
        approval_digest: IntegrityDigest::from_bytes([0xca; 32]),
        policy_revision: 1,
        approval_expires_at: i64::MAX,
        round_index: 0,
    };
    binding.refresh_digests();
    let encrypted = EncryptedToolPayloadV1 {
        key: ProviderJournalKeyBinding::new([0xcb; 16], 1, [0xcc; 16], 1).unwrap(),
        payload: ProviderEncryptedPayload::new(
            [0xcd; 12],
            vec![0; binding.canonical_arguments.len() + 16],
            binding.canonical_arguments.len() as u64,
            binding.arguments_digest.into_bytes(),
        )
        .unwrap(),
    };
    match store.propose_taskrun_tool_invocation(binding, encrypted, &assignment, 1) {
        Err(ToolInvocationStoreError::Cancelled) => {}
        Err(error) => panic!("expected cancellation before stale-version rejection, got {error:?}"),
        Ok(_) => panic!("cancelled task accepted a tool proposal"),
    }
}

include!("taskrun_tool_invocation_positive_ports.rs");
