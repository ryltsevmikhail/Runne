impl TaskRun {
    fn apply_retry_payload(&mut self, payload: &TaskRunEvent) -> Result<(), DomainError> {
        match payload {
            TaskRunEvent::RetryScheduled {
                ordinal,
                old_attempt_id,
                new_attempt_id,
                abandoned_cycle_id,
                step_outcome_ref,
                retry_policy_digest,
                budget_reservation_ref,
                delay_ms,
                due_at_unix_us,
            } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                if self.pending_retry.is_some() {
                    return Err(Self::loop_error(LoopInvariantViolation::PendingRetryExists));
                }
                self.check_attempt_id_unique(new_attempt_id)?;
                let cycle = self
                    .active_cycle
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                if self.active_attempt != Some(*old_attempt_id)
                    || cycle.attempt_id != *old_attempt_id
                    || cycle.cycle_id != *abandoned_cycle_id
                    || step_outcome_ref.cycle_id != *abandoned_cycle_id
                    || !cycle.recorded_outcomes.iter().any(|outcome| {
                        outcome.proposal_index == step_outcome_ref.proposal_index
                            && outcome.step_id == step_outcome_ref.step_id
                            && outcome.outcome_type == StepOutcomeType::FailedBeforeCommit
                    })
                    || budget_reservation_ref.taskrun_id != self.id
                    || budget_reservation_ref.attempt_id != *old_attempt_id
                    || budget_reservation_ref.retry_ordinal != *ordinal
                {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingRetryMismatch,
                    ));
                }
                let pending = PendingRetry {
                    ordinal: *ordinal,
                    old_attempt_id: *old_attempt_id,
                    new_attempt_id: *new_attempt_id,
                    abandoned_cycle_id: *abandoned_cycle_id,
                    step_outcome_ref: step_outcome_ref.clone(),
                    due_at_unix_us: *due_at_unix_us,
                    delay_ms: *delay_ms,
                    budget_reservation_ref: budget_reservation_ref.clone(),
                    retry_policy_digest: *retry_policy_digest,
                };
                self.active_cycle = None;
                self.pending_retry = Some(pending);
                self.state = TaskRunState::Retrying;
            }
            TaskRunEvent::ActivateScheduledRetryAttempt {
                ordinal,
                attempt_id,
                activated_at_unix_us,
            } => {
                self.require_state(TaskRunState::Retrying, payload.kind())?;
                let pending = self
                    .pending_retry
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingPendingRetry))?;
                if pending.ordinal != *ordinal || pending.new_attempt_id != *attempt_id {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingRetryMismatch,
                    ));
                }
                if *activated_at_unix_us < pending.due_at_unix_us {
                    return Err(Self::loop_error(LoopInvariantViolation::RetryNotDue));
                }
                self.check_attempt_id_unique(attempt_id)?;
                self.attempt_history.push(*attempt_id);
                self.active_attempt = Some(*attempt_id);
                self.pending_retry = None;
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::RecoveryResumeStarted {
                new_attempt_id,
                new_generation,
                abandoned_cycle_id,
                context_manifest_ref: _,
                checkpoint_ref: _,
                reconciliation_ref,
            } => {
                self.require_state(TaskRunState::Reconciling, payload.kind())?;
                self.check_attempt_id_unique(new_attempt_id)?;
                self.validate_recovery_ref(reconciliation_ref)?;
                let expected_generation = self
                    .recovery_generation
                    .checked_add(1)
                    .ok_or(DomainError::RecoveryGenerationExhausted)?;
                if expected_generation != *new_generation
                    || self.active_cycle.as_ref().map(|cycle| cycle.cycle_id) != *abandoned_cycle_id
                {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::RecoveryReferenceMismatch,
                    ));
                }
                self.active_cycle = None;
                self.pending_successor = None;
                self.pending_loop_wait = None;
                self.pending_retry = None;
                self.attempt_history.push(*new_attempt_id);
                self.active_attempt = Some(*new_attempt_id);
                self.recovery_generation = *new_generation;
                self.state = TaskRunState::Running;
            },
            _ => unreachable!("retry payload dispatched to wrong handler"),
        };
        Ok(())
    }
}
