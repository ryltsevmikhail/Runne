impl TaskRun {
    pub(super) fn validate_replay_batch(
        events: &[EventEnvelope<TaskRunEvent>],
        index: usize,
        aggregate: &Self,
    ) -> Result<(), DomainError> {
        let event = &events[index];
        let same_command =
            |other: &EventEnvelope<TaskRunEvent>| other.command_id() == event.command_id();
        match event.payload() {
            TaskRunEvent::LoopCycleCompleted { disposition, .. } => {
                if matches!(disposition, LoopDisposition::Continue) {
                    return Ok(());
                }
                let next = events
                    .get(index + 1)
                    .ok_or(DomainError::CorruptCommandBatch)?;
                let valid = match disposition {
                    LoopDisposition::Continue => true,
                    LoopDisposition::Wait { .. } => {
                        matches!(next.payload(), TaskRunEvent::WaitStarted)
                    }
                    LoopDisposition::Complete { .. } => matches!(
                        next.payload(),
                        TaskRunEvent::TaskRunCompleted {
                            result: TerminalResult::Success
                        }
                    ),
                    LoopDisposition::Fail { reason, .. } => matches!(
                        next.payload(),
                        TaskRunEvent::TaskRunFailed {
                            reason: next_reason
                        } if next_reason == reason
                    ),
                };
                if !valid || !same_command(next) {
                    return Err(DomainError::CorruptCommandBatch);
                }
            }
            TaskRunEvent::Resumed if aggregate.pending_loop_wait.is_some() => {
                let next = events
                    .get(index + 1)
                    .ok_or(DomainError::CorruptCommandBatch)?;
                if !matches!(next.payload(), TaskRunEvent::LoopWakeAccepted { .. })
                    || !same_command(next)
                {
                    return Err(DomainError::CorruptCommandBatch);
                }
            }
            TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position,
                integrity_digest,
            } => {
                let recorded = events
                    .get(index + 1)
                    .ok_or(DomainError::CorruptCommandBatch)?;
                let committed = events
                    .get(index + 2)
                    .ok_or(DomainError::CorruptCommandBatch)?;
                let recorded_matches = matches!(
                    recorded.payload(),
                    TaskRunEvent::LoopCheckpointRecorded {
                        checkpoint_id: recorded_id,
                        event_position: recorded_position,
                        integrity_digest: recorded_digest,
                        ..
                    } if recorded_id == checkpoint_id
                        && recorded_position == event_position
                        && recorded_digest == integrity_digest
                );
                let committed_matches = matches!(
                    committed.payload(),
                    TaskRunEvent::LoopCheckpointCommitted {
                        checkpoint_id: committed_id,
                        event_position: committed_position,
                        integrity_digest: committed_digest,
                    } if committed_id == checkpoint_id
                        && committed_position == event_position
                        && committed_digest == integrity_digest
                );
                if !recorded_matches
                    || !committed_matches
                    || !same_command(recorded)
                    || !same_command(committed)
                {
                    return Err(DomainError::CorruptCommandBatch);
                }
            }
            _ => {}
        }
        Ok(())
    }

}
