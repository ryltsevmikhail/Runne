impl TaskRun {
    fn decide_lifecycle(
        &self,
        command: TaskRunCommand,
    ) -> Result<Vec<DomainEventDraft<TaskRunEvent>>, DomainError> {
        let aggregate_id = AggregateId::TaskRun(self.id);
        let draft = |payload: TaskRunEvent, sensitivity: Sensitivity| {
            DomainEventDraft::new(
                aggregate_id.clone(),
                aggregate_id.clone(),
                1,
                sensitivity,
                payload,
            )
        };
        match command {
            TaskRunCommand::Admit => {
                self.require_state(TaskRunState::Queued, TaskRunEventKind::TaskRunAdmitted)?;
                Ok(vec![draft(
                    TaskRunEvent::TaskRunAdmitted,
                    Sensitivity::Public,
                )])
            }

            TaskRunCommand::Queue => {
                self.require_state(TaskRunState::Created, TaskRunEventKind::TaskRunQueued)?;
                Ok(vec![draft(
                    TaskRunEvent::TaskRunQueued,
                    Sensitivity::Public,
                )])
            }

            TaskRunCommand::StartAttempt { attempt_id } => {
                self.require_state(TaskRunState::Admitted, TaskRunEventKind::AttemptStarted)?;
                self.check_attempt_id_unique(&attempt_id)?;
                Ok(vec![draft(
                    TaskRunEvent::AttemptStarted { attempt_id },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::WaitForApproval => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::WaitStarted)?;
                Ok(vec![draft(TaskRunEvent::WaitStarted, Sensitivity::Public)])
            }
            TaskRunCommand::Resume => {
                self.require_state(TaskRunState::Waiting, TaskRunEventKind::Resumed)?;
                if self.pending_loop_wait.is_some() {
                    return Err(DomainError::LoopWakeEvidenceRequired);
                }
                Ok(vec![draft(TaskRunEvent::Resumed, Sensitivity::Public)])
            }
            TaskRunCommand::StartRetry { attempt_id } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::RetryStarted)?;
                self.check_attempt_id_unique(&attempt_id)?;
                Ok(vec![draft(
                    TaskRunEvent::RetryStarted { attempt_id },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CompleteRetry { attempt_id } => {
                self.require_state(TaskRunState::Retrying, TaskRunEventKind::RetryCompleted)?;
                if self.active_attempt != Some(attempt_id)
                    || !self.attempt_history.contains(&attempt_id)
                {
                    return Err(Self::loop_error(LoopInvariantViolation::MissingActiveAttempt));
                }
                if self.pending_retry.is_some() {
                    return Err(Self::loop_error(LoopInvariantViolation::PendingRetryExists));
                }
                Ok(vec![draft(
                    TaskRunEvent::RetryCompleted { attempt_id },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::StartCheckpoint => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::CheckpointStarted)?;
                Ok(vec![draft(
                    TaskRunEvent::CheckpointStarted,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CommitCheckpoint => {
                self.require_state(
                    TaskRunState::Checkpointing,
                    TaskRunEventKind::CheckpointCommitted,
                )?;
                Ok(vec![draft(
                    TaskRunEvent::CheckpointCommitted,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::RequestCancellation => {
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
                        event: TaskRunEventKind::CancellationRequested,
                    });
                }
                Ok(vec![draft(
                    TaskRunEvent::CancellationRequested,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CompleteCancellation => {
                self.require_state(
                    TaskRunState::Cancelling,
                    TaskRunEventKind::CancellationCompleted,
                )?;
                Ok(vec![draft(
                    TaskRunEvent::CancellationCompleted,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::Complete { result } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::TaskRunCompleted)?;
                Ok(vec![draft(
                    TaskRunEvent::TaskRunCompleted { result },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::Fail { reason } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::TaskRunFailed)?;
                Ok(vec![draft(
                    TaskRunEvent::TaskRunFailed { reason },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::FailGeneration { reason } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::TaskRunFailed)?;
                Ok(vec![draft(
                    TaskRunEvent::TaskRunFailed {
                        reason: reason.as_code().to_owned(),
                    },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::StartReconciliation => {
                self.require_state(
                    TaskRunState::Running,
                    TaskRunEventKind::ReconciliationStarted,
                )?;
                Ok(vec![draft(
                    TaskRunEvent::ReconciliationStarted,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CompleteReconciliation => {
                self.require_state(TaskRunState::Reconciling, TaskRunEventKind::Reconciled)?;
                Ok(vec![draft(TaskRunEvent::Reconciled, Sensitivity::Public)])
            }
            TaskRunCommand::MarkUnrecoverable => {
                self.require_state(TaskRunState::Reconciling, TaskRunEventKind::Unrecoverable)?;
                Ok(vec![draft(
                    TaskRunEvent::Unrecoverable,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::UserSupersedeUnknown {
                predecessor_attempt_id,
                successor_taskrun_id,
                acknowledgement_digest,
            } => {
                if !matches!(self.state, TaskRunState::Running | TaskRunState::Cancelling)
                    || self.active_attempt != Some(predecessor_attempt_id)
                {
                    return Err(DomainError::InvalidTransition {
                        from: self.state,
                        event: TaskRunEventKind::UserSupersedeUnknown,
                    });
                }
                Ok(vec![draft(
                    TaskRunEvent::UserSupersedeUnknown {
                        predecessor_attempt_id,
                        successor_taskrun_id,
                        acknowledgement_digest,
                    },
                    Sensitivity::Public,
                )])
            }
            _ => unreachable!("lifecycle command dispatched to wrong handler"),
        }
    }
}
