impl TaskRun {
    fn decide_recovery(
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
            TaskRunCommand::ScheduleRetry {
                new_attempt_id,
                retry_ordinal,
                step_outcome_ref,
                retry_policy_digest,
                budget_reservation_ref,
                delay_ms,
                due_at_unix_us,
            } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::RetryScheduled)?;
                if self.pending_retry.is_some() {
                    return Err(Self::loop_error(LoopInvariantViolation::PendingRetryExists));
                }
                self.check_attempt_id_unique(&new_attempt_id)?;
                let active_attempt = self.active_attempt.ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingActiveAttempt)
                })?;
                let active_cycle = self
                    .active_cycle
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                if step_outcome_ref.cycle_id != active_cycle.cycle_id
                    || !active_cycle.recorded_outcomes.iter().any(|outcome| {
                        outcome.proposal_index == step_outcome_ref.proposal_index
                            && outcome.step_id == step_outcome_ref.step_id
                            && outcome.outcome_type == StepOutcomeType::FailedBeforeCommit
                    })
                    || budget_reservation_ref.taskrun_id != self.id
                    || budget_reservation_ref.attempt_id != active_attempt
                    || budget_reservation_ref.retry_ordinal != retry_ordinal
                {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingRetryMismatch,
                    ));
                }
                Ok(vec![draft(
                    TaskRunEvent::RetryScheduled {
                        ordinal: retry_ordinal,
                        old_attempt_id: active_attempt,
                        new_attempt_id,
                        abandoned_cycle_id: active_cycle.cycle_id,
                        step_outcome_ref,
                        retry_policy_digest,
                        budget_reservation_ref,
                        delay_ms,
                        due_at_unix_us,
                    },
                    Sensitivity::Sensitive,
                )])
            }
            TaskRunCommand::ActivateScheduledRetryAttempt {
                retry_ordinal,
                now_unix_us,
            } => {
                self.require_state(
                    TaskRunState::Retrying,
                    TaskRunEventKind::ActivateScheduledRetryAttempt,
                )?;
                let pending = self
                    .pending_retry
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingPendingRetry))?;
                if pending.ordinal != retry_ordinal {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingRetryMismatch,
                    ));
                }
                if now_unix_us < pending.due_at_unix_us {
                    return Err(Self::loop_error(LoopInvariantViolation::RetryNotDue));
                }
                Ok(vec![draft(
                    TaskRunEvent::ActivateScheduledRetryAttempt {
                        ordinal: retry_ordinal,
                        attempt_id: pending.new_attempt_id,
                        activated_at_unix_us: now_unix_us,
                    },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CommitRecoveryResume {
                new_attempt_id,
                context_manifest_ref,
                checkpoint_ref,
                reconciliation_ref,
            } => {
                self.require_state(
                    TaskRunState::Reconciling,
                    TaskRunEventKind::RecoveryResumeStarted,
                )?;
                self.check_attempt_id_unique(&new_attempt_id)?;
                self.validate_recovery_ref(&reconciliation_ref)?;
                let new_generation = self
                    .recovery_generation
                    .checked_add(1)
                    .ok_or(DomainError::RecoveryGenerationExhausted)?;
                Ok(vec![draft(
                    TaskRunEvent::RecoveryResumeStarted {
                        new_attempt_id,
                        new_generation,
                        abandoned_cycle_id: self.active_cycle.as_ref().map(|cycle| cycle.cycle_id),
                        context_manifest_ref,
                        checkpoint_ref,
                        reconciliation_ref,
                    },
                    Sensitivity::Sensitive,
                )])
            }
            TaskRunCommand::CommitLoopCheckpoint {
                checkpoint_id,
                event_position,
                body,
                integrity_digest,
            } => {
                self.require_state(
                    TaskRunState::Running,
                    TaskRunEventKind::LoopCheckpointStarted,
                )?;
                if self.pending_loop_checkpoint.is_some() {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingCheckpointExists,
                    ));
                }
                self.validate_checkpoint_body(&body)?;
                Ok(vec![
                    draft(
                        TaskRunEvent::LoopCheckpointStarted {
                            checkpoint_id,
                            event_position,
                            integrity_digest,
                        },
                        Sensitivity::Sensitive,
                    ),
                    draft(
                        TaskRunEvent::LoopCheckpointRecorded {
                            checkpoint_id,
                            event_position,
                            body,
                            integrity_digest,
                        },
                        Sensitivity::Sensitive,
                    ),
                    draft(
                        TaskRunEvent::LoopCheckpointCommitted {
                            checkpoint_id,
                            event_position,
                            integrity_digest,
                        },
                        Sensitivity::Sensitive,
                    ),
                ])
            },
            _ => unreachable!("recovery command dispatched to wrong handler"),
        }
    }
}
