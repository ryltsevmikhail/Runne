fn canonical_payload_schema() -> Value {
    let id = uuid_v7_schema;
    let optional_id = nullable_uuid_v7_schema;
    let text = || string_schema(65_536);
    let reason = || string_schema(4_096);
    let variants = vec![
        payload_variant("conversation.created", &[("workspaceId", id())]),
        payload_variant(
            "conversation.message.appended",
            &[
                ("attemptId", id()),
                ("messageId", id()),
                ("role", enum_schema(&["user", "assistant"])),
                ("taskRunId", id()),
                ("text", text()),
            ],
        ),
        payload_variant(
            "conversation.generation.failed",
            &[
                ("attemptId", id()),
                ("reason", reason()),
                ("taskRunId", id()),
            ],
        ),
        payload_variant("conversation.closed", &[]),
        payload_variant("taskRun.created", &[]),
        payload_variant("taskRun.queued", &[]),
        payload_variant("taskRun.admitted", &[]),
        payload_variant("taskRun.attempt.started", &[("attemptId", id())]),
        payload_variant("taskRun.wait.started", &[]),
        payload_variant("taskRun.resumed", &[]),
        payload_variant("taskRun.retry.started", &[("attemptId", id())]),
        payload_variant("taskRun.retry.completed", &[("attemptId", id())]),
        payload_variant("taskRun.checkpoint.started", &[]),
        payload_variant("taskRun.checkpoint.committed", &[]),
        payload_variant("taskRun.cancellation.requested", &[]),
        payload_variant("taskRun.cancellation.completed", &[]),
        payload_variant(
            "taskRun.completed",
            &[
                ("outcome", json!({"const": "success", "type": "string"})),
                ("reason", json!({"type": "null"})),
            ],
        ),
        payload_variant(
            "taskRun.completed",
            &[
                ("outcome", json!({"const": "failure", "type": "string"})),
                ("reason", reason()),
            ],
        ),
        payload_variant("taskRun.failed", &[("reason", reason())]),
        payload_variant("taskRun.budget.exhausted", &[]),
        payload_variant("taskRun.policy.denied", &[]),
        payload_variant("taskRun.reconciliation.started", &[]),
        payload_variant("taskRun.reconciliation.completed", &[]),
        payload_variant("taskRun.unrecoverable", &[]),
        payload_variant("taskRun.cancelled", &[]),
        payload_variant(
            "taskRun.loop.cycle.started",
            &[
                ("attemptId", id()),
                ("cycleId", id()),
                ("parentCycleId", optional_id()),
                ("sequence", positive_integer_schema()),
            ],
        ),
        payload_variant(
            "taskRun.context.committed",
            &[
                ("cycleId", id()),
                ("manifestId", id()),
                ("revision", positive_integer_schema()),
            ],
        ),
        payload_variant(
            "taskRun.plan.committed",
            &[
                ("cycleId", id()),
                (
                    "expectedProposalIndexes",
                    json!({
                        "items": {"minimum": 0, "type": "integer"},
                        "type": "array",
                        "uniqueItems": true,
                    }),
                ),
                ("planId", id()),
                ("revision", positive_integer_schema()),
            ],
        ),
        payload_variant(
            "taskRun.step.outcome.recorded",
            &[
                ("cycleId", id()),
                (
                    "outcome",
                    enum_schema(&[
                        "succeeded",
                        "failed_before_commit",
                        "failed_after_commit",
                        "uncertain",
                        "cancelled",
                    ]),
                ),
                ("proposalIndex", json!({"minimum": 0, "type": "integer"})),
                ("stepId", id()),
            ],
        ),
        payload_variant(
            "taskRun.loop.cycle.completed",
            &[
                ("attemptId", id()),
                ("cycleId", id()),
                (
                    "disposition",
                    enum_schema(&["continue", "wait", "complete", "fail"]),
                ),
            ],
        ),
        payload_variant(
            "taskRun.next.cycle.created",
            &[
                ("attemptId", id()),
                ("parentCycleId", id()),
                ("sequence", positive_integer_schema()),
                ("successorCycleId", id()),
            ],
        ),
        payload_variant(
            "taskRun.retry.scheduled",
            &[
                ("abandonedCycleId", id()),
                ("delayMillis", json!({"minimum": 0, "type": "integer"})),
                ("dueAtUnixMicros", json!({"type": "integer"})),
                ("newAttemptId", id()),
                ("oldAttemptId", id()),
                ("ordinal", positive_integer_schema()),
            ],
        ),
        payload_variant(
            "taskRun.retry.attempt.activated",
            &[
                ("activatedAtUnixMicros", json!({"type": "integer"})),
                ("attemptId", id()),
                ("ordinal", positive_integer_schema()),
            ],
        ),
        payload_variant(
            "taskRun.recovery.resume.started",
            &[
                ("abandonedCycleId", optional_id()),
                ("newAttemptId", id()),
                ("newGeneration", positive_integer_schema()),
            ],
        ),
        payload_variant("taskRun.loop.checkpoint.started", &[("checkpointId", id())]),
        payload_variant(
            "taskRun.loop.checkpoint.recorded",
            &[("checkpointId", id())],
        ),
        payload_variant(
            "taskRun.loop.checkpoint.committed",
            &[("checkpointId", id())],
        ),
        payload_variant(
            "taskRun.loop.wake.accepted",
            &[
                ("cycleId", id()),
                ("evidenceId", id()),
                (
                    "source",
                    enum_schema(&[
                        "external_input",
                        "approval",
                        "child_task_run",
                        "timer",
                        "reconciliation",
                    ]),
                ),
            ],
        ),
    ];
    json!({"oneOf": variants})
}
