use runne_application::ports::TextGenerationPhase;
use runne_domain::{conversation::ConversationEvent, task_run::TaskRunEvent};
use runne_runtime_client::CanonicalId;
use runne_store::codec::{
    ConversationEventCodec, StoreCodec, TaskRunEventCodec, TextGenerationReceiptCodec,
};
use std::path::Path;

fn task_bytes(task: CanonicalId) -> [u8; 16] {
    uuid::Uuid::parse_str(&task.to_string())
        .expect("task id")
        .into_bytes()
}

fn read_count(database: &Path, task: CanonicalId, query: &str) -> usize {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only D2 invocation view");
    connection
        .query_row(query, [task_bytes(task).as_slice()], |row| row.get(0))
        .expect("read D2 invocation count")
}

pub(super) fn invocation_count(database: &Path, task: CanonicalId) -> usize {
    read_count(
        database,
        task,
        "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1",
    )
}

pub(super) fn taskrun_head(database: &Path, task: CanonicalId) -> u64 {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only TaskRun head");
    connection
        .query_row(
            "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [task_bytes(task).as_slice()],
            |row| row.get(0),
        )
        .and_then(|version: i64| {
            u64::try_from(version).map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .expect("read TaskRun stream version")
}

pub(super) fn result_count(database: &Path, task: CanonicalId) -> usize {
    read_count(
        database,
        task,
        "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND state='result'",
    )
}

pub(super) fn truncated_audit_count(database: &Path, task: CanonicalId) -> usize {
    read_count(
        database,
        task,
        "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND state='audit_only' AND result_truncated=1",
    )
}

pub(super) fn invocation_state(database: &Path, task: CanonicalId) -> String {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only invocation state");
    connection
        .query_row(
            "SELECT state FROM taskrun_tool_invocations WHERE taskrun_id=?1",
            [task_bytes(task).as_slice()],
            |row| row.get::<_, String>(0),
        )
        .expect("invocation state")
}

pub(super) fn tool_budget_effects_used(database: &Path, task: CanonicalId) -> Option<u32> {
    use rusqlite::OptionalExtension as _;
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only budget view");
    connection
        .query_row(
            "SELECT effects_used FROM taskrun_tool_budgets WHERE taskrun_id=?1",
            [task_bytes(task).as_slice()],
            |row| row.get(0),
        )
        .optional()
        .expect("read optional tool budget usage")
}

pub(super) fn assert_failure_projection(database: &Path, task: CanonicalId) {
    assert_terminal_failure_projection(
        database,
        task,
        runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
    );
}

/// A restart that already carries the durable auto-admitted read result
/// settles the interrupted create as an interruption, not a pre-effect
/// rejection.
pub(super) fn assert_interrupted_by_restart_projection(database: &Path, task: CanonicalId) {
    assert_terminal_failure_projection(
        database,
        task,
        runne_domain::conversation::GenerationFailureReason::InterruptedByRestart,
    );
}

fn assert_terminal_failure_projection(
    database: &Path,
    task: CanonicalId,
    expected_reason: runne_domain::conversation::GenerationFailureReason,
) {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only D2 failure projection view");
    let task_bytes = task_bytes(task);
    let (task_head, terminal_event): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT current_version,last_event_id FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read failed TaskRun head");
    let conversation_bytes: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
            [task_bytes.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|payload| {
            let submitted = TaskRunEventCodec
                .decode(&payload)
                .expect("decode submit event");
            let TaskRunEvent::TaskRunSubmitted {
                conversation_id, ..
            } = submitted
            else {
                panic!("TaskRun starts with submission");
            };
            conversation_id.as_bytes().to_vec()
        })
        .expect("read submitted TaskRun");
    let (_, failed_payload, command_id, sequence): (Vec<u8>, Vec<u8>, Vec<u8>, i64) = connection
        .query_row(
            "SELECT event_id,payload,command_id,sequence FROM events WHERE aggregate_type=2 AND aggregate_id=?1 ORDER BY sequence DESC LIMIT 1",
            [conversation_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read terminal Conversation event");
    let terminal = ConversationEventCodec
        .decode(&failed_payload)
        .expect("decode Conversation terminal");
    let failed_attempt = match terminal {
        ConversationEvent::GenerationFailed {
            taskrun_id,
            attempt_id,
            reason,
        } if taskrun_id.as_bytes() == &task_bytes && reason == expected_reason => attempt_id,
        _ => panic!("original Conversation has exact D2 failure event"),
    };
    let outcome: Vec<u8> = connection
        .query_row(
            "SELECT command_outcome FROM command_receipts WHERE command_id=?1",
            [command_id.as_slice()],
            |row| row.get(0),
        )
        .expect("read original Generate receipt outcome");
    let receipt = TextGenerationReceiptCodec
        .decode(&outcome)
        .expect("decode original Generate receipt");
    assert_eq!(receipt.phase, TextGenerationPhase::Rejected);
    assert_eq!(receipt.attempt_id, failed_attempt);
    assert_eq!(i64::try_from(receipt.taskrun_version).ok(), Some(task_head));
    assert_eq!(
        i64::try_from(receipt.conversation_version).ok(),
        Some(sequence)
    );
    let occupation: (String, Option<Vec<u8>>, i64) = connection
        .query_row(
            "SELECT state,release_event_id,terminal_version FROM taskrun_assignment_occupations o JOIN taskrun_terminal_settlement_receipts r USING(taskrun_id,fence,attempt_id,node_id,node_epoch) WHERE o.taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read terminal occupation settlement");
    assert_eq!(occupation.0, "released");
    assert_eq!(occupation.1.as_deref(), Some(terminal_event.as_slice()));
    assert_eq!(occupation.2, task_head);
}

pub(super) fn release_intent_count(database: &Path, task: CanonicalId) -> usize {
    read_count(
        database,
        task,
        "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND release_started=1",
    )
}

pub(super) fn managed_area_launch_count(database: &Path, task: CanonicalId) -> usize {
    read_count(
        database,
        task,
        "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND local_stop_state<>0",
    )
}

pub(super) fn local_stop_state(database: &Path, task: CanonicalId) -> Option<i64> {
    use rusqlite::OptionalExtension as _;
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only local-stop receipt view");
    connection
        .query_row(
            "SELECT local_stop_state FROM taskrun_tool_invocations WHERE taskrun_id=?1",
            [task_bytes(task).as_slice()],
            |row| row.get(0),
        )
        .optional()
        .expect("read local-stop receipt")
}
