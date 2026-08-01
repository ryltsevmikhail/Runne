impl TaskRun {
    fn apply_loop_payload(&mut self, payload: &TaskRunEvent) -> Result<(), DomainError> {
        match payload {
            TaskRunEvent::LoopCycleStarted {
                cycle_id,
                attempt_id,
                sequence,
                parent_cycle_id,
            } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                if self.active_attempt != Some(*attempt_id) {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::MissingActiveAttempt,
                    ));
                }
                if self.active_cycle.is_some() {
                    return Err(Self::loop_error(LoopInvariantViolation::ActiveCycleExists));
                }
                if self
                    .cycle_history
                    .iter()
                    .any(|entry| entry.cycle_id == *cycle_id)
                {
                    return Err(Self::loop_error(LoopInvariantViolation::CycleAlreadyUsed));
                }

                match self.pending_successor.as_ref() {
                    Some(pending) => {
                        if pending.successor_cycle_id != *cycle_id
                            || pending.attempt_id != *attempt_id
                            || pending.sequence != *sequence
                            || Some(pending.parent_cycle_id) != *parent_cycle_id
                        {
                            return Err(Self::loop_error(
                                LoopInvariantViolation::SuccessorReservationMismatch,
                            ));
                        }
                    }
                    None => {
                        if *sequence != 0 || parent_cycle_id.is_some() {
                            return Err(Self::loop_error(
                                LoopInvariantViolation::SuccessorReservationMismatch,
                            ));
                        }
                        if self
                            .cycle_history
                            .iter()
                            .any(|entry| entry.attempt_id == *attempt_id)
                        {
                            return Err(Self::loop_error(
                                LoopInvariantViolation::AttemptAlreadyHasCycle,
                            ));
                        }
                    }
                }

                let history_entry = CycleHistoryEntry {
                    cycle_id: *cycle_id,
                    attempt_id: *attempt_id,
                    sequence: *sequence,
                    parent_cycle_id: *parent_cycle_id,
                };
                let active_cycle = ActiveLoopCycle {
                    cycle_id: *cycle_id,
                    attempt_id: *attempt_id,
                    sequence: *sequence,
                    parent_cycle_id: *parent_cycle_id,
                    state: LoopCycleState::Observing,
                    context_manifest_ref: None,
                    plan_revision_ref: None,
                    expected_proposal_indexes: Vec::new(),
                    recorded_outcomes: Vec::new(),
                };
                self.pending_successor = None;
                self.cycle_history.push(history_entry);
                self.active_cycle = Some(active_cycle);
            }
            TaskRunEvent::ContextCommitted {
                cycle_id,
                manifest_ref,
            } => {
                self.validate_context_commit(*cycle_id, manifest_ref)?;
                let cycle = self
                    .active_cycle
                    .as_mut()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                cycle.context_manifest_ref = Some(manifest_ref.clone());
                cycle.state = LoopCycleState::Proposing;
            }
            TaskRunEvent::PlanCommitted {
                cycle_id,
                plan_revision_ref,
                input_digest: _,
                output_digest: _,
                expected_proposal_indexes,
            } => {
                self.validate_plan_commit(*cycle_id, plan_revision_ref, expected_proposal_indexes)?;
                let next_state = if expected_proposal_indexes.is_empty() {
                    LoopCycleState::Evaluating
                } else {
                    LoopCycleState::Acting
                };
                let cycle = self
                    .active_cycle
                    .as_mut()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                cycle.plan_revision_ref = Some(plan_revision_ref.clone());
                cycle.expected_proposal_indexes = expected_proposal_indexes.clone();
                cycle.state = next_state;
            }
            TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome } => {
                self.validate_step_outcome(*cycle_id, outcome)?;
                let cycle = self
                    .active_cycle
                    .as_mut()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                cycle.recorded_outcomes.push(outcome.clone());
                let all_recorded = cycle.expected_proposal_indexes.iter().all(|index| {
                    cycle
                        .recorded_outcomes
                        .iter()
                        .any(|outcome| outcome.proposal_index == *index)
                });
                if all_recorded {
                    cycle.state = LoopCycleState::Evaluating;
                }
            }
            TaskRunEvent::LoopCycleCompleted {
                cycle_id,
                attempt_id,
                disposition,
            } => {
                let validated_attempt = self.validate_cycle_completion(*cycle_id, disposition)?;
                if validated_attempt != *attempt_id {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::CycleBindingMismatch,
                    ));
                }
                let cycle = self
                    .active_cycle
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                let completed = CompletedCycleRef {
                    cycle_id: *cycle_id,
                    attempt_id: *attempt_id,
                    sequence: cycle.sequence,
                    disposition: disposition.clone(),
                    accepted_wake_evidence: None,
                    successor_allocated: false,
                };
                let pending_wait = match disposition {
                    LoopDisposition::Wait { wake_condition, .. } => Some(PendingLoopWait {
                        cycle_id: *cycle_id,
                        wake_condition: wake_condition.clone(),
                    }),
                    _ => None,
                };
                self.active_cycle = None;
                self.last_completed_cycle = Some(completed);
                self.pending_loop_wait = pending_wait;
            }
            TaskRunEvent::NextCycleCreated {
                parent_cycle_id,
                successor_cycle_id,
                attempt_id,
                sequence,
            } => {
                let completed = self.validate_successor(*parent_cycle_id, *successor_cycle_id)?;
                let expected_sequence = completed.sequence.checked_add(1).ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::SuccessorReservationMismatch)
                })?;
                if completed.attempt_id != *attempt_id || expected_sequence != *sequence {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::SuccessorReservationMismatch,
                    ));
                }
                let pending = PendingSuccessorCycle {
                    parent_cycle_id: *parent_cycle_id,
                    successor_cycle_id: *successor_cycle_id,
                    attempt_id: *attempt_id,
                    sequence: *sequence,
                };
                let completed = self.last_completed_cycle.as_mut().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingCompletedCycle)
                })?;
                completed.successor_allocated = true;
                self.pending_successor = Some(pending);
            },
            _ => unreachable!("loop payload dispatched to wrong handler"),
        };
        Ok(())
    }
}
