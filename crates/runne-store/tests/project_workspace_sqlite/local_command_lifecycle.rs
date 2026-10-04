#![cfg(target_os = "linux")]

use super::claim::node_registration;
use super::support::*;
use runne_application::commands::{CancelTaskRunInput, CommandOutcome};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{
    CompleteClaimedTaskRunCancellationInput, EventStore, ExecutionNodeId, RuntimeAuthorityId,
    TaskRunAssignmentIdentity, TaskRunClaimResult,
};
use runne_domain::id::{ConversationId, WorkspaceId};

#[test]
fn cancel_request_can_fence_launch_intent_before_gate_release() {
    let (database, runtime_authority) =
        database_with_node_authority("local-command-cancel-launch-intent");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0x60).into_bytes());
    ConversationService::new(
        database.store.clone(),
        database.store.clone(),
        runtime_authority.clone(),
    )
    .create_from_application(
        &task_context(0x60, "local-command-launch-intent-conversation"),
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            command_id: command(0x60),
            idempotency_key: key("local-command-launch-intent-conversation"),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let command = runne_domain::task_run::TaskRunLocalCommand::new(
        runne_domain::task_run::TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap();
    let task_runs = runne_application::service::TaskRunService::new(
        database.store.clone(),
        database.store.clone(),
        database.store.clone(),
        runtime_authority.clone(),
    );
    let outcome = task_runs
        .submit_task_run(
            &task_context(0x61, "local-command-cancel-launch-intent-submit"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: runne_domain::task_run::TaskRunInput::new("description".into())
                    .unwrap()
                    .with_local_command(command)
                    .unwrap(),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submitted local TaskRun")
    };
    let (node_id, node_epoch) = node_registration(&database);
    let claimed = task_runs
        .claim_task_run(
            &task_context(0x62, "local-command-cancel-launch-intent-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &database.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claimed else {
        panic!("fresh claim")
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: ExecutionNodeId(node_id.clone()),
        node_epoch,
        fence: claim.fence,
    };
    task_runs
        .cancel_task_run(
            &task_context(0x63, "local-command-cancel-launch-intent-cancel"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: claim.new_version,
            },
        )
        .unwrap();
    let node = uuid::Uuid::parse_str(&node_id).unwrap();
    let area_root =
        runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup()
            .expect("delegated Linux cgroup-v2 root");
    let area = area_root
        .create_area(
            runne_platform::process_managed_area::ManagedAreaBinding::new(
                *taskrun_id.as_bytes(),
                *claim.attempt_id.as_bytes(),
                [0x6a; 16],
            )
            .unwrap(),
        )
        .expect("private attempt cgroup");
    let area_identity = area.identity().to_bytes();
    let connection = database.connection();
    connection
        .execute(
            "UPDATE taskrun_local_command_attempts SET state='approved' WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE taskrun_local_command_attempts SET attempt_id=?1,node_id=?2,node_epoch=?3,fence=?4,managed_area_identity=?5,state='launch_intent' WHERE taskrun_id=?6",
            rusqlite::params![claim.attempt_id.as_bytes(),node.as_bytes(),node_epoch as i64,claim.fence.0 as i64,area_identity.as_slice(),taskrun_id.as_bytes()],
        )
        .unwrap();
    database
        .store
        .request_local_command_stop(&identity, &area_identity)
        .unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "cancel_requested"
    );
    let (recovery_node, recovery_epoch) = node_registration(&database);
    assert_eq!(recovery_node, node_id);
    let candidate = database
        .store
        .scan_local_command_recovery(None, 16)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.identity.taskrun_id == taskrun_id)
        .expect("durable area attempt is recoverable");
    let recovery_store = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        runtime_authority.clone(),
        guard(),
    )
    .unwrap();
    recovery_store
        .request_local_command_stop_recovery(
            &candidate,
            &ExecutionNodeId(recovery_node),
            recovery_epoch,
        )
        .unwrap();
    recovery_store
        .confirm_local_command_stopped_recovery(
            &candidate,
            &ExecutionNodeId(node_id),
            recovery_epoch,
            area.prove_empty().unwrap(),
        )
        .unwrap();
    let recovery_task_runs = runne_application::service::TaskRunService::new(
        recovery_store.clone(),
        recovery_store.clone(),
        recovery_store.clone(),
        runtime_authority.clone(),
    );
    let completed = recovery_task_runs
        .complete_claimed_taskrun_cancellation(
            &task_context(0x64, "local-command-cancel-launch-intent-complete"),
            CompleteClaimedTaskRunCancellationInput {
                taskrun_id,
                expected_version: recovery_store
                    .load_task_run(taskrun_id)
                    .unwrap()
                    .current_version,
            },
            &recovery_store,
        )
        .unwrap();
    let version = match completed {
        runne_application::ports::CompleteQueuedCancellationResult::Committed(receipt)
        | runne_application::ports::CompleteQueuedCancellationResult::Duplicate(receipt) => {
            receipt.new_version
        }
    };
    assert_eq!(version, 6);
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(
            &recovery_store.load_task_run(taskrun_id).unwrap().events
        )
        .unwrap()
        .state(),
        runne_domain::task_run::TaskRunState::Cancelled,
        "stop proof is followed by the normal terminal-event service"
    );
    let cleanup = recovery_store
        .scan_local_command_terminal_cleanup(None, 16)
        .unwrap();
    let terminal_candidate = cleanup
        .iter()
        .find(|item| item.identity.taskrun_id == taskrun_id)
        .expect("cancellation receipt schedules retained area cleanup");
    assert_eq!(
        terminal_candidate.state,
        runne_store::store::LocalCommandAttemptState::Cancelled
    );
    assert_eq!(terminal_candidate.exit_code, None);
    let identity = runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(
        &terminal_candidate.area_identity,
    )
    .unwrap();
    assert!(area_root.remove_area_if_present(identity.clone()).unwrap());
    assert!(
        area_root
            .reopen_area(
                identity,
                binding_for_candidate(&terminal_candidate.area_identity)
            )
            .is_err()
    );
}

fn binding_for_candidate(bytes: &[u8]) -> runne_platform::process_managed_area::ManagedAreaBinding {
    let identity =
        runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(bytes).unwrap();
    let fields = identity.to_bytes();
    runne_platform::process_managed_area::ManagedAreaBinding::new(
        fields[52..68].try_into().unwrap(),
        fields[68..84].try_into().unwrap(),
        fields[84..100].try_into().unwrap(),
    )
    .unwrap()
}

fn database_with_node_authority(name: &str) -> (Database, RuntimeAuthorityId) {
    let file = crate::validated_reopen::ValidatedTestDatabase::new(name);
    let identity = crate::validated_reopen::initialize_database_identity(file.path()).unwrap();
    let connection =
        crate::validated_reopen::open_validated_connection(file.path(), identity).unwrap();
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT authority_id FROM _authority WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let authority =
        RuntimeAuthorityId(uuid::Uuid::from_bytes(bytes.try_into().unwrap()).to_string());
    drop(connection);
    let store =
        crate::validated_reopen::reopen_store(file.path(), identity, authority.clone(), guard())
            .unwrap();
    (
        Database {
            file,
            identity,
            store,
        },
        authority,
    )
}
