#![cfg(target_os = "linux")]

use super::claim::node_registration;
use super::support::*;
use runne_application::commands::CancelTaskRunInput;
use runne_application::ports::{
    CompleteClaimedTaskRunCancellationInput, EventStore, ExecutionNodeId,
    TaskRunAssignmentIdentity, TaskRunClaimResult,
};

#[tokio::test(flavor = "current_thread")]
async fn cancel_request_can_fence_launch_intent_before_gate_release() {
    let prepared = super::legacy_local_command_fixture::prepare_with_node_authority(
        "local-command-cancel-launch-intent",
        0x60,
        0x6c,
        [3; 32],
        [4; 32],
    )
    .await;
    let database = prepared.database;
    let taskrun_id = prepared.taskrun_id;
    let (node_id, node_epoch) = node_registration(&database);
    let runtime_authority = runne_application::ports::RuntimeAuthorityId(node_id.clone());
    let runtime_store = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        runtime_authority.clone(),
        guard(),
    )
    .unwrap();
    let task_runs = runne_application::service::TaskRunService::new(
        runtime_store.clone(),
        runtime_store.clone(),
        runtime_store.clone(),
        runtime_authority.clone(),
    );
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
            &runtime_store,
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
    runtime_store
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
    let candidate = runtime_store
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
