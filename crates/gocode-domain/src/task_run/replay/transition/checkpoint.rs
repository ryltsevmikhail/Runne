impl TaskRun {
    fn apply_checkpoint_payload(&mut self, payload: &TaskRunEvent) -> Result<(), DomainError> {
        match payload {
            TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position,
                integrity_digest,
            } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                if self.pending_loop_checkpoint.is_some() {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingCheckpointExists,
                    ));
                }
                self.pending_loop_checkpoint = Some(PendingLoopCheckpoint {
                    checkpoint_id: *checkpoint_id,
                    start_position: *event_position,
                    expected_integrity_digest: *integrity_digest,
                    recorded_integrity_digest: None,
                });
            }
            TaskRunEvent::LoopCheckpointRecorded {
                checkpoint_id,
                event_position,
                body,
                integrity_digest,
            } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                let pending = self.pending_loop_checkpoint.as_ref().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingPendingCheckpoint)
                })?;
                if pending.checkpoint_id != *checkpoint_id
                    || pending.start_position != *event_position
                    || pending.expected_integrity_digest != *integrity_digest
                    || pending.recorded_integrity_digest.is_some()
                {
                    return Err(Self::loop_error(LoopInvariantViolation::CheckpointMismatch));
                }
                self.validate_checkpoint_body(body)?;
                let pending = self.pending_loop_checkpoint.as_mut().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingPendingCheckpoint)
                })?;
                pending.recorded_integrity_digest = Some(*integrity_digest);
            }
            TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id,
                event_position,
                integrity_digest,
            } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                let pending = self.pending_loop_checkpoint.as_ref().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingPendingCheckpoint)
                })?;
                if pending.checkpoint_id != *checkpoint_id
                    || pending.start_position != *event_position
                    || pending.expected_integrity_digest != *integrity_digest
                    || pending.recorded_integrity_digest != Some(*integrity_digest)
                {
                    return Err(Self::loop_error(LoopInvariantViolation::CheckpointMismatch));
                }
                self.pending_loop_checkpoint = None;
            }
            TaskRunEvent::LoopWakeAccepted {
                cycle_id,
                wake_evidence_ref,
            } => {
                if *cycle_id != wake_evidence_ref.cycle_id {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::WakeEvidenceMismatch,
                    ));
                }
                self.validate_wake_evidence(wake_evidence_ref)?;
                let completed = self.last_completed_cycle.as_ref().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingCompletedCycle)
                })?;
                if completed.cycle_id != *cycle_id
                    || !matches!(completed.disposition, LoopDisposition::Wait { .. })
                    || completed.accepted_wake_evidence.is_some()
                {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::WakeEvidenceMismatch,
                    ));
                }
                let completed = self.last_completed_cycle.as_mut().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingCompletedCycle)
                })?;
                completed.accepted_wake_evidence = Some(wake_evidence_ref.clone());
                self.pending_loop_wait = None;
            },
            _ => unreachable!("checkpoint payload dispatched to wrong handler"),
        };
        Ok(())
    }
}
