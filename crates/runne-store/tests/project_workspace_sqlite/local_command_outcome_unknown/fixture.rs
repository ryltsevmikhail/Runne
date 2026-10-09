use super::super::support::*;
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{
    EventStore, ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunClaimResult,
};
use runne_domain::id::{ApprovalId, ConversationId, WorkspaceId};
use runne_platform::process_managed_area::LinuxManagedArea;
use runne_store::store::LocalCommandRecoveryCandidate;
use runne_store::store::StoreTransaction;
use runne_store::{ProjectWorkspaceStore, store::LocalCommandApprovalBinding};

pub struct PreparedUnknown {
    pub database: Database,
    pub taskrun_id: runne_domain::id::TaskRunId,
    pub node: String,
    pub candidate: LocalCommandRecoveryCandidate,
    pub area: LinuxManagedArea,
    pub area_bytes: Vec<u8>,
    pub assignment: TaskRunAssignmentIdentity,
    pub recovery_epoch: u64,
    pub recovery_store: StoreTransaction,
}

pub async fn prepare() -> PreparedUnknown {
    let donor = Database::new("local-command-outcome-unknown-recovery-donor");
    let repository = donor.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0x81).into_bytes());
    ConversationService::new(donor.store.clone(), donor.store.clone(), authority())
        .create_from_application(
            &task_context(0x81, "local-unknown-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(0x81),
                idempotency_key: key("local-unknown-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let (node, _) = super::super::claim::node_registration(&donor);
    let runtime_authority = runne_application::ports::RuntimeAuthorityId(node.clone());
    let runtime_store = crate::validated_reopen::reopen_store(
        donor.file.path(),
        donor.identity,
        runtime_authority.clone(),
        guard(),
    )
    .unwrap();
    let tasks = runne_application::service::TaskRunService::new(
        runtime_store.clone(),
        runtime_store.clone(),
        runtime_store.clone(),
        runtime_authority.clone(),
    );
    let local = runne_domain::task_run::TaskRunLocalCommand::new(
        runne_domain::task_run::TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap();
    let submitted = tasks
        .submit_task_run(
            &task_context(0x82, "local-unknown-submit"),
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
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submitted
    else {
        panic!("TaskRun submission expected")
    };
    let approval_id = ApprovalId::from_bytes(command(0x8c).into_bytes());
    let binding = LocalCommandApprovalBinding {
        command_digest: local.intent_digest(),
        executable_digest: [3; 32],
        workspace_version: 1,
        admitted_root_version: 1,
        admitted_root_identity: [4; 32],
        trust_epoch: 1,
        trust_revision: 1,
        source_policy_version: 2,
        command_policy_version: 1,
        approval_id: *approval_id.as_bytes(),
    };
    super::super::legacy_local_command_fixture::create_pending_approval(
        &ProjectWorkspaceStore::from_store(runtime_store.clone()),
        taskrun_id,
        &local,
        approval_id,
    )
    .await;
    let database = super::super::legacy_local_command_fixture::migrate_pending(
        &donor,
        taskrun_id,
        approval_id,
        binding,
        "local-command-outcome-unknown-recovery",
    );
    let (node, first_epoch) = super::super::claim::node_registration(&database);
    assert_eq!(node, runtime_authority.0);
    let runtime_store = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        runtime_authority.clone(),
        guard(),
    )
    .unwrap();
    let tasks = runne_application::service::TaskRunService::new(
        runtime_store.clone(),
        runtime_store.clone(),
        runtime_store.clone(),
        runtime_authority,
    );
    let claimed_result = tasks
        .claim_task_run(
            &task_context(0x83, "local-unknown-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node.clone()),
                node_epoch: first_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &runtime_store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claimed_result else {
        panic!("fresh exact local TaskRun claim")
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: ExecutionNodeId(node.clone()),
        node_epoch: first_epoch,
        fence: claim.fence,
    };
    let claimed = runtime_store.load_task_run(taskrun_id).unwrap();
    assert_eq!(claimed.current_version, 4);
    let root = runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup()
        .expect("delegated Linux cgroup-v2 root");
    let area = root
        .create_area(
            runne_platform::process_managed_area::ManagedAreaBinding::new(
                *taskrun_id.as_bytes(),
                *assignment.attempt_id.as_bytes(),
                [0x82; 16],
            )
            .unwrap(),
        )
        .expect("private cgroup for the exact attempt");
    let area_bytes = area.identity().to_bytes().to_vec();
    database
        .store
        .bind_local_command_approval(
            taskrun_id,
            binding,
            runne_store::store::LocalCommandAttemptState::Approved,
        )
        .unwrap();
    database
        .store
        .persist_local_command_launch_intent(&assignment, claimed.current_version, &area_bytes)
        .unwrap();
    let connection = database.connection();
    for state in ["release_reserved", "running"] {
        connection
            .execute(
                "UPDATE taskrun_local_command_attempts SET state=?1 WHERE taskrun_id=?2",
                rusqlite::params![state, taskrun_id.as_bytes()],
            )
            .unwrap();
    }
    let candidate = database
        .store
        .scan_local_command_recovery(None, 8)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.identity.taskrun_id == taskrun_id)
        .expect("durable may-have-released attempt");
    assert_eq!(candidate.exit_code, None);
    let next_epoch = super::super::claim::node_registration(&database).1;
    assert!(next_epoch > candidate.identity.node_epoch);
    let recovery_epoch = super::super::claim::node_registration(&database).1;
    assert!(recovery_epoch > next_epoch);
    let recovery_store = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        runne_application::ports::RuntimeAuthorityId(node.clone()),
        guard(),
    )
    .unwrap();
    PreparedUnknown {
        database,
        taskrun_id,
        node,
        candidate,
        area,
        area_bytes,
        assignment,
        recovery_epoch,
        recovery_store,
    }
}
