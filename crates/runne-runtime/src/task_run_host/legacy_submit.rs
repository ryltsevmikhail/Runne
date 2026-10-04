use super::*;

pub(super) async fn submit_legacy(
    handle: &RuntimeHandle,
    context: TaskRunCommandContext,
    command: LegacySubmitTaskRunCommand,
) -> Result<TaskRunCommandAck, TaskRunHostError> {
    let outcome = handle
        .submit_task_run_legacy(
            into_application_context(context)?,
            LegacySubmitTaskRunInput {
                conversation_id: command.conversation_id,
                workspace_id: command.workspace_id,
            },
        )
        .await
        .map_err(map_runtime_error)?;
    match outcome {
        CommandOutcome::TaskRunSubmitted {
            taskrun_id,
            new_version,
        } => Ok(TaskRunCommandAck {
            taskrun_id,
            new_version,
            kind: TaskRunCommandAckKind::Submitted,
        }),
        _ => Err(TaskRunHostError::InvariantViolation),
    }
}
