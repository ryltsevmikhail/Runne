use runne_application::commands::CommandOutcome;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, EventStore, ExecutionNodeId, IdGenerator, IdempotencyScope, OperationTag,
    PrincipalId, TaskRunAssignmentIdentity, TaskRunAssignmentPort, TaskRunClaimResult,
    TaskRunNoEffectReleaseError, TaskRunNoEffectReleasePort, TaskRunNoEffectReleaseRequest,
    TaskRunNoEffectReleaseResult,
};
use runne_domain::event::{Sensitivity, UncommittedEvent};
use runne_domain::id::AggregateId;
use runne_domain::task_run::TaskRunEvent;

use super::claim::node_registration;
use super::submit_fence::submit_task_run;
use super::support::*;

#[path = "no_effect_release/restart/cancelled_head.rs"]
mod cancelled_head;
mod integrity;
mod receipt_tests;
mod release_tests;
mod restart;

fn claim(
    database: &Database,
    taskrun: runne_domain::id::TaskRunId,
    tail: u8,
    node: &str,
    epoch: u64,
) -> (TaskRunAssignmentIdentity, u64) {
    let result = database
        .task_runs()
        .claim_task_run(
            &task_context(tail, "release-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id: taskrun,
                expected_version: 2,
                node_id: ExecutionNodeId(node.into()),
                node_epoch: epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 20_000,
            },
            &database.store,
        )
        .unwrap();
    let receipt = match result {
        TaskRunClaimResult::Committed(r) => r,
        _ => panic!("fresh claim"),
    };
    (
        TaskRunAssignmentIdentity {
            taskrun_id: taskrun,
            attempt_id: receipt.attempt_id,
            node_id: receipt.node_id,
            node_epoch: receipt.node_epoch,
            fence: receipt.fence,
        },
        receipt.new_version,
    )
}

fn release_request(
    database: &Database,
    identity: TaskRunAssignmentIdentity,
    version: u64,
    tail: u8,
) -> TaskRunNoEffectReleaseRequest {
    let context = task_context(tail, "no-effect-release");
    let event_id = database.store.next_event_ids(1).unwrap().remove(0);
    let stream = database.store.load_task_run(identity.taskrun_id).unwrap();
    TaskRunNoEffectReleaseRequest {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key.clone(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: authority(),
            principal_id: PrincipalId("owner".into()),
            operation: OperationTag::TaskRunNoEffectRelease,
            aggregate_scope: AggregateScope::ExistingTaskRun {
                taskrun_id: identity.taskrun_id,
            },
        },
        command_fingerprint: CommandFingerprint::from_bytes([tail; 32]),
        expected_version: version,
        identity: identity.clone(),
        failure_event: UncommittedEvent::from_parts(
            event_id,
            AggregateId::TaskRun(identity.taskrun_id),
            AggregateId::TaskRun(identity.taskrun_id),
            stream.last_event_id,
            context.command_id,
            context.idempotency_key,
            1,
            context.actor,
            Sensitivity::Public,
            TaskRunEvent::TaskRunFailed {
                reason: "dispatch_not_started".into(),
            },
        ),
    }
}
