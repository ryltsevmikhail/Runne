use super::*;

pub(super) async fn supersede(
    handle: &RuntimeHandle,
    context: TaskRunCommandContext,
    command: SupersedeUnknownTaskRunCommand,
) -> Result<TaskRunCommandAck, TaskRunHostError> {
    let outcome = handle
        .supersede_unknown_task_run(
            into_application_context(context)?,
            SupersedeUnknownTaskRunInput {
                predecessor_taskrun_id: command.predecessor_taskrun_id,
                expected_predecessor_version: command.expected_predecessor_version,
                acknowledgment: match command.acknowledgment {
                    UnknownSuccessorAcknowledgment::DuplicateExecutionAndCostV1 => {
                        runne_application::commands::UnknownSuccessorAcknowledgmentV1::DuplicateExecutionAndCostV1
                    }
                },
            },
        )
        .await
        .map_err(map_runtime_error)?;
    match outcome {
        CommandOutcome::UnknownSuccessorCreated {
            predecessor_taskrun_id,
            predecessor_version,
            successor_taskrun_id,
            successor_version,
            ..
        } => Ok(TaskRunCommandAck {
            taskrun_id: successor_taskrun_id,
            new_version: successor_version,
            kind: TaskRunCommandAckKind::UnknownSuccessorCreated {
                predecessor_taskrun_id,
                predecessor_version,
                successor_taskrun_id,
                successor_version,
            },
        }),
        _ => Err(TaskRunHostError::InvariantViolation),
    }
}
