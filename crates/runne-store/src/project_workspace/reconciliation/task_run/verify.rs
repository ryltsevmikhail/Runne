use super::*;

pub(super) fn verify_committed_events(
    transaction: &Transaction<'_>,
    witness: &CommandReconciliationWitness,
    authoritative: &AuthoritativeCommandOutcome,
    context: &CommandReconciliationContext,
) -> Result<(), Error> {
    match witness.view() {
        CommandReconciliationWitnessRef::CancelTaskRun { task_run_id, .. } => verify_event(
            transaction,
            task_run_id,
            authoritative_version(authoritative)?,
            context,
        ),
        CommandReconciliationWitnessRef::SubmitTaskRun {
            conversation_id,
            workspace_id,
            input,
        } => {
            let Some(taskrun_id) = submitted_taskrun_id(&authoritative.view()) else {
                return Err(Error::InvariantViolation);
            };
            for (sequence, is_queued) in [(1_i64, false), (2_i64, true)] {
                let payload: Vec<u8> = transaction
                    .query_row(
                        "SELECT payload FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1
                         AND sequence = ?2 AND command_id = ?3",
                        params![
                            taskrun_id.as_bytes(),
                            sequence,
                            context.command_id().as_bytes()
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|_| Error::InvariantViolation)?;
                let decoded = TaskRunEventCodec.decode(&payload);
                let matches_expected = match (decoded, input) {
                    (
                        Ok(TaskRunEvent::TaskRunSubmitted {
                            conversation_id: stored_conversation,
                            workspace_id: stored_workspace,
                            input: stored_input,
                        }),
                        Some(input),
                    ) => {
                        !is_queued
                            && stored_conversation == conversation_id
                            && stored_workspace == workspace_id
                            && stored_input == *input
                    }
                    (Ok(TaskRunEvent::TaskRunCreated), None) => !is_queued,
                    (Ok(TaskRunEvent::TaskRunQueued), _) => is_queued,
                    _ => false,
                };
                if !matches_expected {
                    return Err(Error::InvariantViolation);
                }
            }
            Ok(())
        }
        _ => Err(Error::InvariantViolation),
    }
}
