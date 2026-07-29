use gocode_api::{
    ApiActor, ApiPrincipalId, CanonicalTaskRunState, CanonicalTerminalResult,
    CompleteTaskRunCommand, CreateTaskRunCommand, ExistingTaskRunCommand,
    MAX_CANONICAL_TERMINAL_REASON_BYTES, TaskRunCommandAck, TaskRunCommandAckKind,
    TaskRunCommandContext, TaskRunHostError, TaskRunSnapshot,
};
use gocode_domain::id::{
    AttemptId, CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId,
};

const COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
const TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-000000000004";
const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000005";

#[test]
fn command_contract_retains_exact_validated_identities() {
    let context = TaskRunCommandContext {
        command_id: COMMAND_ID.parse::<CommandId>().unwrap(),
        idempotency_key: IdempotencyKey::new("request-1").unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("gocode-cli").unwrap(),
    };
    let create = CreateTaskRunCommand {
        conversation_id: CONVERSATION_ID.parse::<ConversationId>().unwrap(),
        workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
    };
    let existing = ExistingTaskRunCommand {
        taskrun_id: TASKRUN_ID.parse::<TaskRunId>().unwrap(),
        expected_version: 4,
    };
    let complete = CompleteTaskRunCommand {
        taskrun_id: existing.taskrun_id,
        expected_version: existing.expected_version,
        result: CanonicalTerminalResult::Failure {
            reason: "deterministic failure".to_owned(),
        },
    };

    assert_eq!(context.command_id.to_string(), COMMAND_ID);
    assert_eq!(context.idempotency_key.as_str(), "request-1");
    assert_eq!(context.principal.as_str(), "local-owner");
    assert_eq!(context.actor.as_str(), "gocode-cli");
    assert_eq!(create.conversation_id.to_string(), CONVERSATION_ID);
    assert_eq!(create.workspace_id.to_string(), WORKSPACE_ID);
    assert_eq!(complete.taskrun_id.to_string(), TASKRUN_ID);
    assert_eq!(complete.expected_version, 4);
    assert_eq!(
        complete.result,
        CanonicalTerminalResult::Failure {
            reason: "deterministic failure".to_owned(),
        }
    );
}

#[test]
fn taskrun_snapshot_uses_closed_state_and_terminal_values() {
    let taskrun_id = TASKRUN_ID.parse::<TaskRunId>().unwrap();
    let attempt_id = ATTEMPT_ID.parse::<AttemptId>().unwrap();
    let snapshot = TaskRunSnapshot {
        taskrun_id,
        state: CanonicalTaskRunState::Succeeded,
        stream_version: 5,
        active_attempt_id: Some(attempt_id),
        terminal_result: Some(CanonicalTerminalResult::Success),
    };

    assert_eq!(snapshot.taskrun_id, taskrun_id);
    assert_eq!(snapshot.state.as_str(), "succeeded");
    assert_eq!(snapshot.stream_version, 5);
    assert_eq!(snapshot.active_attempt_id, Some(attempt_id));
    assert_eq!(
        snapshot.terminal_result,
        Some(CanonicalTerminalResult::Success)
    );
}

#[test]
fn command_ack_names_the_exact_committed_transition() {
    let taskrun_id = TASKRUN_ID.parse::<TaskRunId>().unwrap();
    let attempt_id = ATTEMPT_ID.parse::<AttemptId>().unwrap();
    let ack = TaskRunCommandAck {
        taskrun_id,
        new_version: 4,
        kind: TaskRunCommandAckKind::AttemptStarted { attempt_id },
    };

    assert_eq!(ack.taskrun_id, taskrun_id);
    assert_eq!(ack.new_version, 4);
    assert_eq!(
        ack.kind,
        TaskRunCommandAckKind::AttemptStarted { attempt_id }
    );
}

#[test]
fn host_errors_have_stable_redacted_codes() {
    let values = [
        (TaskRunHostError::NotFound, "task_run_not_found"),
        (TaskRunHostError::Conflict, "task_run_conflict"),
        (TaskRunHostError::Backpressure, "runtime_backpressure"),
        (TaskRunHostError::Unavailable, "runtime_unavailable"),
        (
            TaskRunHostError::InvariantViolation,
            "runtime_invariant_violation",
        ),
    ];

    for (error, expected) in values {
        assert_eq!(error.code(), expected);
        assert!(!error.code().contains('/'));
        assert!(!error.code().contains('\\'));
    }
}

#[test]
fn canonical_terminal_reason_limit_is_transport_owned() {
    assert_eq!(MAX_CANONICAL_TERMINAL_REASON_BYTES, 4096);
}
