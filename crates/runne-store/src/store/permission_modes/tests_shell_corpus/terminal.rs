//! Domain completion through the public native terminal UoW, never direct state writes.
use super::fixture::{Fixture, command_id, key};
use runne_application::{commands::CommandOutcome, fingerprint::CommandFingerprint, ports::*};
use runne_domain::{
    command::{TaskRunCommand, TerminalResult},
    event::{Actor, CommandContext, materialize_batch},
    id::TaskRunId,
    task_run::{TaskRun, TaskRunEvent, TaskRunState},
};

pub(super) fn success(f: &Fixture, taskrun_id: TaskRunId) -> CommandCommit {
    let stream = f.store.load_task_run(taskrun_id).unwrap();
    let task = TaskRun::replay(&stream.events).unwrap();
    assert_eq!(task.state(), TaskRunState::Running);
    let result = TerminalResult::Success;
    let drafts = task
        .decide(TaskRunCommand::Complete {
            result: result.clone(),
        })
        .unwrap();
    let ids = f.store.next_event_ids(drafts.len()).unwrap();
    let context = CommandContext {
        command_id: command_id(),
        idempotency_key: key("r08-shell-terminal"),
        actor: Actor::new("test:r08-shell-fixture").unwrap(),
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

pub(super) fn assert_success(f: &Fixture, taskrun_id: TaskRunId, version: u64) {
    let stream = f.store.load_task_run(taskrun_id).unwrap();
    assert_eq!(stream.current_version, version);
    assert!(matches!(
        stream.events.last().unwrap().payload(),
        TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success
        }
    ));
    // Replay validates the full public event history, including its terminal event.
    TaskRun::replay(&stream.events).unwrap();
    let capture = f
        .store
        .load_local_command_permission_capture(taskrun_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        capture.state,
        crate::store::LocalCommandAttemptState::Completed
    );
    let cleanup = f
        .store
        .scan_local_command_terminal_cleanup(None, 8)
        .unwrap();
    assert_eq!(cleanup.len(), 1);
    assert_eq!(cleanup[0].identity.taskrun_id, taskrun_id);
    assert_eq!(cleanup[0].exit_code, Some(0));
    assert_eq!(
        cleanup[0].state,
        crate::store::LocalCommandAttemptState::Completed
    );
}
