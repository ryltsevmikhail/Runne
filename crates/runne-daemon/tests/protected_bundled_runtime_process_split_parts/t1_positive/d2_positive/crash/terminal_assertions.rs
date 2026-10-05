pub(super) fn assert_one_interrupted(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
) {
    use runne_store::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};
    let task_id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let conv_id = uuid::Uuid::parse_str(&conversation.to_string())
        .expect("Conversation UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only terminal event view");
    let task_payload: Vec<u8> = db.query_row(
        "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence DESC LIMIT 1",
        [task_id.as_slice()], |row| row.get(0),
    ).expect("read TaskRun terminal event");
    assert!(
        matches!(TaskRunEventCodec.decode(&task_payload), Ok(runne_domain::task_run::TaskRunEvent::TaskRunFailed { reason }) if reason == "interrupted_by_restart")
    );
    let payloads = db
        .prepare("SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1")
        .expect("prepare Conversation terminal events")
        .query_map([conv_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .expect("query Conversation terminal events")
        .collect::<Result<Vec<_>, _>>()
        .expect("read Conversation terminal events");
    let failures = payloads.iter().filter(|payload| matches!(
        ConversationEventCodec.decode(payload),
        Ok(runne_domain::conversation::ConversationEvent::GenerationFailed { taskrun_id, reason: runne_domain::conversation::GenerationFailureReason::InterruptedByRestart, .. }) if taskrun_id.to_string() == task.to_string()
    )).count();
    assert_eq!(
        failures, 1,
        "one durable local InterruptedByRestart receipt"
    );
}

pub(super) fn assert_one_cancelled(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
) {
    use runne_store::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};
    let task_id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let conv_id = uuid::Uuid::parse_str(&conversation.to_string())
        .expect("Conversation UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only cancellation view");
    let task_payload: Vec<u8> = db.query_row("SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence DESC LIMIT 1", [task_id.as_slice()], |row| row.get(0)).expect("read TaskRun cancellation event");
    assert!(matches!(
        TaskRunEventCodec.decode(&task_payload),
        Ok(runne_domain::task_run::TaskRunEvent::CancellationCompleted)
    ));
    let payloads = db
        .prepare("SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1")
        .expect("prepare Conversation cancellation events")
        .query_map([conv_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .expect("query Conversation events")
        .collect::<Result<Vec<_>, _>>()
        .expect("read Conversation cancellation events");
    let count = payloads.iter().filter(|payload| matches!(ConversationEventCodec.decode(payload), Ok(runne_domain::conversation::ConversationEvent::GenerationFailed { taskrun_id, reason: runne_domain::conversation::GenerationFailureReason::Cancelled, .. }) if taskrun_id.to_string() == task.to_string())).count();
    assert_eq!(count, 1, "one durable cancellation receipt");
}
