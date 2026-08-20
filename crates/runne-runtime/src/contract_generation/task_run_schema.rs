fn task_run_schema() -> Value {
    let terminal_result = json!({
        "oneOf": [
            closed_object(json!({"type": {"const": "success", "type": "string"}}), &["type"]),
            closed_object(
                json!({
                    "reason": {"maxLength": 4096, "minLength": 1, "type": "string"},
                    "type": {"const": "failure", "type": "string"},
                }),
                &["reason", "type"],
            ),
        ],
    });
    let mut schema = closed_object(
        json!({
            "activeAttemptId": nullable(uuid_v7_schema()),
            "state": {
                "enum": [
                    "created",
                    "queued",
                    "admitted",
                    "running",
                    "waiting",
                    "retrying",
                    "checkpointing",
                    "cancelling",
                    "reconciling",
                    "succeeded",
                    "failed",
                    "cancelled",
                    "budget_exhausted",
                    "policy_denied",
                    "unrecoverable",
                ],
                "type": "string",
            },
            "streamVersion": positive_integer_schema(),
            "taskRunId": uuid_v7_schema(),
            "terminalResult": nullable(terminal_result),
        }),
        &[
            "activeAttemptId",
            "state",
            "streamVersion",
            "taskRunId",
            "terminalResult",
        ],
    );
    let object = schema.as_object_mut().unwrap();
    object.insert("$id".to_owned(), json!("gocode://schemas/task-run-v1"));
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert("title".to_owned(), json!("TaskRun Snapshot V1"));
    schema
}

fn nullable(schema: Value) -> Value {
    json!({"oneOf": [schema, {"type": "null"}]})
}
