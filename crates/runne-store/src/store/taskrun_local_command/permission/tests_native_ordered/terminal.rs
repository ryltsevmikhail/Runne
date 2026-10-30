//! Canonical domain event materialization; no daemon/service is started.
use super::super::fixture::{Fixture, command_id, key};
use runne_application::{commands::CommandOutcome, fingerprint::CommandFingerprint, ports::*};
use runne_domain::{
    command::{TaskRunCommand, TerminalResult},
    event::{Actor, CommandContext, materialize_batch},
    id::TaskRunId,
    task_run::TaskRun,
};

pub(super) fn policy_stopped(f: &Fixture, taskrun_id: TaskRunId) -> CommandCommit {
    let stream = f.store.load_task_run(taskrun_id).unwrap();
    let task = TaskRun::replay(&stream.events).unwrap();
    let reason = "local_command_policy_stopped_v1".to_owned();
    let result = TerminalResult::Failure {
        reason: reason.clone(),
    };
    let drafts = task.decide(TaskRunCommand::Fail { reason }).unwrap();
    let ids = f.store.next_event_ids(drafts.len()).unwrap();
    let context = CommandContext {
        command_id: command_id(),
        idempotency_key: key("r05-policy-terminal"),
        actor: Actor::new("test:r05-native-fixture").unwrap(),
    };
    let events = materialize_batch(drafts, &ids, stream.last_event_id, &context).unwrap();
    CommandCommit {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key,
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: f.scope.runtime_authority_id.clone(),
            principal_id: PrincipalId(f.principal.as_str().into()),
            operation: OperationTag::Complete,
            aggregate_scope: AggregateScope::ExistingTaskRun { taskrun_id },
        },
        command_fingerprint: CommandFingerprint::for_complete(
            &taskrun_id,
            &result,
            stream.current_version,
        )
        .unwrap(),
        expected_version: stream.current_version,
        events,
        command_result: CommandOutcome::TaskRunCompleted {
            taskrun_id,
            new_version: stream.current_version + 1,
        },
    }
}
