#[allow(clippy::too_many_lines)]
fn validate_task_run_payload(
    event_type: &str,
    value: &serde_json::Value,
) -> Result<TaskRunReplayPayload, ReplayClientError> {
    let object = payload_object(value)?;
    let kind = TaskRunTimelineKind::parse(event_type)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    let attempt_id = match event_type {
        "taskRun.created"
        | "taskRun.queued"
        | "taskRun.admitted"
        | "taskRun.wait.started"
        | "taskRun.resumed"
        | "taskRun.checkpoint.started"
        | "taskRun.checkpoint.committed"
        | "taskRun.cancellation.requested"
        | "taskRun.cancellation.completed"
        | "taskRun.budget.exhausted"
        | "taskRun.policy.denied"
        | "taskRun.reconciliation.started"
        | "taskRun.reconciliation.completed"
        | "taskRun.unrecoverable"
        | "taskRun.cancelled" => {
            validate_exact_keys(object, &["type"])?;
            None
        }
        "taskRun.attempt.started" | "taskRun.retry.started" | "taskRun.retry.completed" => {
            validate_exact_keys(object, &["attemptId", "type"])?;
            Some(uuid_field(object, "attemptId")?)
        }
        "taskRun.completed" => {
            validate_exact_keys(object, &["outcome", "reason", "type"])?;
            match string_field(object, "outcome")? {
                "success" if object.get("reason").is_some_and(serde_json::Value::is_null) => None,
                "failure" => {
                    bounded_string_field(object, "reason", MAXIMUM_REASON_BYTES)?;
                    None
                }
                _ => {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::SchemaMismatch,
                    ));
                }
            }
        }
        "taskRun.failed" => {
            validate_exact_keys(object, &["reason", "type"])?;
            bounded_string_field(object, "reason", MAXIMUM_REASON_BYTES)?;
            None
        }
        "taskRun.loop.cycle.started" => {
            validate_exact_keys(
                object,
                &["attemptId", "cycleId", "parentCycleId", "sequence", "type"],
            )?;
            uuid_field(object, "attemptId")?;
            uuid_field(object, "cycleId")?;
            optional_uuid_field(object, "parentCycleId")?;
            positive_u64_field(object, "sequence")?;
            Some(uuid_field(object, "attemptId")?)
        }
        "taskRun.context.committed" => {
            validate_exact_keys(object, &["cycleId", "manifestId", "revision", "type"])?;
            uuid_field(object, "cycleId")?;
            uuid_field(object, "manifestId")?;
            positive_u64_field(object, "revision")?;
            None
        }
        "taskRun.plan.committed" => {
            validate_exact_keys(
                object,
                &[
                    "cycleId",
                    "expectedProposalIndexes",
                    "planId",
                    "revision",
                    "type",
                ],
            )?;
            uuid_field(object, "cycleId")?;
            uuid_field(object, "planId")?;
            positive_u64_field(object, "revision")?;
            unique_u32_array_field(object, "expectedProposalIndexes")?;
            None
        }
        "taskRun.step.outcome.recorded" => {
            validate_exact_keys(
                object,
                &["cycleId", "outcome", "proposalIndex", "stepId", "type"],
            )?;
            uuid_field(object, "cycleId")?;
            uuid_field(object, "stepId")?;
            u32_field(object, "proposalIndex")?;
            enum_field(
                object,
                "outcome",
                &[
                    "succeeded",
                    "failed_before_commit",
                    "failed_after_commit",
                    "uncertain",
                    "cancelled",
                ],
            )?;
            None
        }
        "taskRun.loop.cycle.completed" => {
            validate_exact_keys(object, &["attemptId", "cycleId", "disposition", "type"])?;
            uuid_field(object, "attemptId")?;
            uuid_field(object, "cycleId")?;
            enum_field(
                object,
                "disposition",
                &["continue", "wait", "complete", "fail"],
            )?;
            Some(uuid_field(object, "attemptId")?)
        }
        "taskRun.next.cycle.created" => {
            validate_exact_keys(
                object,
                &[
                    "attemptId",
                    "parentCycleId",
                    "sequence",
                    "successorCycleId",
                    "type",
                ],
            )?;
            uuid_field(object, "attemptId")?;
            uuid_field(object, "parentCycleId")?;
            uuid_field(object, "successorCycleId")?;
            positive_u64_field(object, "sequence")?;
            Some(uuid_field(object, "attemptId")?)
        }
        "taskRun.retry.scheduled" => {
            validate_exact_keys(
                object,
                &[
                    "abandonedCycleId",
                    "delayMillis",
                    "dueAtUnixMicros",
                    "newAttemptId",
                    "oldAttemptId",
                    "ordinal",
                    "type",
                ],
            )?;
            uuid_field(object, "abandonedCycleId")?;
            uuid_field(object, "newAttemptId")?;
            uuid_field(object, "oldAttemptId")?;
            u64_field(object, "delayMillis")?;
            i64_field(object, "dueAtUnixMicros")?;
            positive_u64_field(object, "ordinal")?;
            Some(uuid_field(object, "newAttemptId")?)
        }
        "taskRun.retry.attempt.activated" => {
            validate_exact_keys(
                object,
                &["activatedAtUnixMicros", "attemptId", "ordinal", "type"],
            )?;
            uuid_field(object, "attemptId")?;
            i64_field(object, "activatedAtUnixMicros")?;
            positive_u64_field(object, "ordinal")?;
            Some(uuid_field(object, "attemptId")?)
        }
        "taskRun.recovery.resume.started" => {
            validate_exact_keys(
                object,
                &["abandonedCycleId", "newAttemptId", "newGeneration", "type"],
            )?;
            optional_uuid_field(object, "abandonedCycleId")?;
            uuid_field(object, "newAttemptId")?;
            positive_u64_field(object, "newGeneration")?;
            Some(uuid_field(object, "newAttemptId")?)
        }
        "taskRun.loop.checkpoint.started"
        | "taskRun.loop.checkpoint.recorded"
        | "taskRun.loop.checkpoint.committed" => {
            validate_exact_keys(object, &["checkpointId", "type"])?;
            uuid_field(object, "checkpointId")?;
            None
        }
        "taskRun.loop.wake.accepted" => {
            validate_exact_keys(object, &["cycleId", "evidenceId", "source", "type"])?;
            uuid_field(object, "cycleId")?;
            uuid_field(object, "evidenceId")?;
            enum_field(
                object,
                "source",
                &[
                    "external_input",
                    "approval",
                    "child_task_run",
                    "timer",
                    "reconciliation",
                ],
            )?;
            None
        }
        _ => {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::SchemaMismatch,
            ));
        }
    };
    Ok(TaskRunReplayPayload { kind, attempt_id })
}
