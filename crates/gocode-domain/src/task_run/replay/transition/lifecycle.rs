impl TaskRun {
    fn apply_lifecycle_payload(&mut self, payload: &TaskRunEvent) -> Result<(), DomainError> {
        match payload {
            TaskRunEvent::TaskRunCreated => {
                self.state = TaskRunState::Created;
            }
            TaskRunEvent::TaskRunQueued => {
                self.require_state(TaskRunState::Created, payload.kind())?;
                self.state = TaskRunState::Queued;
            }
            TaskRunEvent::TaskRunAdmitted => {
                self.require_state(TaskRunState::Queued, payload.kind())?;
                self.state = TaskRunState::Admitted;
            }
            TaskRunEvent::AttemptStarted { attempt_id } => {
                self.require_state(TaskRunState::Admitted, payload.kind())?;
                self.check_attempt_id_unique(attempt_id)?;
                self.attempt_history.push(*attempt_id);
                self.active_attempt = Some(*attempt_id);
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::WaitStarted => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.state = TaskRunState::Waiting;
            }
            TaskRunEvent::Resumed => {
                self.require_state(TaskRunState::Waiting, payload.kind())?;
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::RetryStarted { attempt_id } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.check_attempt_id_unique(attempt_id)?;
                self.attempt_history.push(*attempt_id);
                self.active_attempt = Some(*attempt_id);
                self.state = TaskRunState::Retrying;
            }
            TaskRunEvent::RetryCompleted { attempt_id } => {
                self.require_state(TaskRunState::Retrying, payload.kind())?;
                if self.active_attempt != Some(*attempt_id)
                    || !self.attempt_history.contains(attempt_id)
                {
                    return Err(Self::loop_error(LoopInvariantViolation::MissingActiveAttempt));
                }
                self.active_attempt = Some(*attempt_id);
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::CheckpointStarted => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.state = TaskRunState::Checkpointing;
            }
            TaskRunEvent::CheckpointCommitted => {
                self.require_state(TaskRunState::Checkpointing, payload.kind())?;
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::CancellationRequested => {
                // Valid from: running, waiting, retrying, admitted, queued
                let valid = matches!(
                    self.state,
                    TaskRunState::Running
                        | TaskRunState::Waiting
                        | TaskRunState::Retrying
                        | TaskRunState::Admitted
                        | TaskRunState::Queued
                );
                if !valid {
                    return Err(DomainError::InvalidTransition {
                        from: self.state,
                        event: payload.kind(),
                    });
                }
                if self.state == TaskRunState::Retrying {
                    self.pending_retry = None;
                }
                self.state = TaskRunState::Cancelling;
            }
            TaskRunEvent::CancellationCompleted => {
                self.require_state(TaskRunState::Cancelling, payload.kind())?;
                self.active_attempt = None;
                self.state = TaskRunState::Cancelled;
            }
            TaskRunEvent::TaskRunCompleted { result } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.terminal_result = Some(result.clone());
                self.active_attempt = None;
                self.state = TaskRunState::Succeeded;
            }
            TaskRunEvent::TaskRunFailed { reason: _ } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.active_attempt = None;
                self.state = TaskRunState::Failed;
            }
            TaskRunEvent::BudgetExhausted => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.active_attempt = None;
                self.state = TaskRunState::BudgetExhausted;
            }
            TaskRunEvent::PolicyDenied => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.active_attempt = None;
                self.state = TaskRunState::PolicyDenied;
            }
            TaskRunEvent::ReconciliationStarted => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.state = TaskRunState::Reconciling;
            }
            TaskRunEvent::Reconciled => {
                self.require_state(TaskRunState::Reconciling, payload.kind())?;
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::Unrecoverable => {
                self.require_state(TaskRunState::Reconciling, payload.kind())?;
                self.active_attempt = None;
                self.state = TaskRunState::Unrecoverable;
            }
            TaskRunEvent::TaskRunCancelled => {
                // Valid from: admitted, queued, waiting, retrying
                let valid = matches!(
                    self.state,
                    TaskRunState::Admitted
                        | TaskRunState::Queued
                        | TaskRunState::Waiting
                        | TaskRunState::Retrying
                );
                if !valid {
                    return Err(DomainError::InvalidTransition {
                        from: self.state,
                        event: payload.kind(),
                    });
                }
                self.pending_retry = None;
                self.active_attempt = None;
                self.state = TaskRunState::Cancelled;
            },
            _ => unreachable!("lifecycle payload dispatched to wrong handler"),
        };
        Ok(())
    }
}
