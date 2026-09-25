use super::claim::node_registration;
use super::submit_fence::submit_task_run;
use super::support::*;
use runne_application::commands::{CancelTaskRunInput, CommandOutcome};
use runne_application::ports::{
    ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunAssignmentPort, TaskRunClaimResult,
    TaskRunLeaseRenewal,
};
use runne_application::service::ClaimTaskRunInput;

#[test]
fn dispatch_and_renewal_replay_reject_a_cancelled_taskrun() {
    let database = Database::new("taskrun-assignment-cancelled");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let outcome = submit_task_run(&database, 0x9b, "assignment-cancel-source");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submit outcome expected");
    };
    let (node_id, node_epoch) = node_registration(&database);
    let context = task_context(0x9c, "assignment-cancel-claim");
    let TaskRunClaimResult::Committed(receipt) = database
        .task_runs()
        .claim_task_run(
            &context,
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &database.store,
        )
        .unwrap()
    else {
        panic!("claim expected");
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        fence: receipt.fence,
    };
    database
        .store
        .prepare_taskrun_dispatch(identity.clone())
        .unwrap();
    let renewal = TaskRunLeaseRenewal {
        identity: identity.clone(),
        renewal_id: runne_domain::id::CommandId::from_bytes([0x9d; 16]),
        lease_duration_ms: 30_000,
    };
    database
        .store
        .renew_taskrun_assignment_lease(renewal.clone())
        .unwrap();
    database
        .task_runs()
        .cancel_task_run(
            &task_context(0x9e, "assignment-cancel-run"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 4,
            },
        )
        .unwrap();
    assert_eq!(
        database.store.prepare_taskrun_dispatch(identity),
        Err(runne_application::ports::TaskRunAssignmentError::StaleAssignment)
    );
    assert_eq!(
        database.store.renew_taskrun_assignment_lease(renewal),
        Err(runne_application::ports::TaskRunAssignmentError::StaleAssignment)
    );
}
