async fn get_task_run(
    State(state): State<Arc<MockState>>,
    Path(task_run_id): Path<String>,
) -> axum::Json<Value> {
    let mut inner = state.inner.lock().expect("mock state");
    let value = if inner.task_run_snapshots.len() > 1 {
        inner.task_run_snapshots.remove(0)
    } else {
        inner
            .task_run_snapshots
            .first()
            .cloned()
            .unwrap_or_else(|| task_run_snapshot_json(&task_run_id, "running", 1, &Value::Null))
    };
    axum::Json(value)
}

pub fn task_run_snapshot_json(
    task_run_id: &str,
    state: &str,
    version: u64,
    terminal: &Value,
) -> Value {
    let active_attempt = if state == "running" {
        json!("018f2e3a-7000-7000-8000-000000000131")
    } else {
        Value::Null
    };
    json!({
        "taskRunId": task_run_id,
        "state": state,
        "streamVersion": version,
        "activeAttemptId": active_attempt,
        "terminalResult": terminal,
    })
}

pub fn task_run_event(task_run_id: &str, sequence: u64, kind: &str) -> Value {
    let aggregate = uuid::Uuid::parse_str(task_run_id).expect("TaskRun ID");
    let event_id = format!("018f2e3a-7000-7000-8002-{sequence:012x}");
    json!({
        "aggregateId": task_run_id,
        "aggregateType": "taskRun",
        "causationEventId": null,
        "correlationId": "018f2e3a-7000-7000-8000-000000000130",
        "correlationType": "conversation",
        "cursor": taskrun_cursor(&hex::encode(aggregate.as_bytes()), &event_id, sequence),
        "eventId": event_id,
        "eventType": kind,
        "integrityDigest": "11".repeat(32),
        "payload": {"type": kind},
        "replayBindingId": "018f2e3a700070008000000000000121",
        "schemaVersion": 1,
        "sensitivity": "public",
        "sequence": sequence,
        "timestampUnixMicros": 1_722_330_000_000_000_i64 + i64::try_from(sequence).unwrap(),
    })
}
