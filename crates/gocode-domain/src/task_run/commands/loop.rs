impl TaskRun {
    fn decide_loop(
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
            TaskRunCommand::StartLoopCycle { cycle_id } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::LoopCycleStarted)?;
                let attempt_id = self.active_attempt.ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingActiveAttempt)
                })?;
                if self.active_cycle.is_some() {
                    return Err(Self::loop_error(LoopInvariantViolation::ActiveCycleExists));
                }
                if self
                    .cycle_history
                    .iter()
                    .any(|entry| entry.cycle_id == cycle_id)
                {
                    return Err(Self::loop_error(LoopInvariantViolation::CycleAlreadyUsed));
                }

                let (sequence, parent_cycle_id) = if let Some(pending) =
                    self.pending_successor.as_ref()
                {
                    if pending.successor_cycle_id != cycle_id || pending.attempt_id != attempt_id {
                        return Err(Self::loop_error(
                            LoopInvariantViolation::SuccessorReservationMismatch,
                        ));
                    }
                    (pending.sequence, Some(pending.parent_cycle_id))
                } else {
                    if self
                        .cycle_history
                        .iter()
                        .any(|entry| entry.attempt_id == attempt_id)
                    {
                        return Err(Self::loop_error(
                            LoopInvariantViolation::AttemptAlreadyHasCycle,
                        ));
                    }
                    (0, None)
                };

                Ok(vec![draft(
                    TaskRunEvent::LoopCycleStarted {
                        cycle_id,
                        attempt_id,
                        sequence,
                        parent_cycle_id,
                    },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CommitContext {
                cycle_id,
                manifest_ref,
            } => {
                self.validate_context_commit(cycle_id, &manifest_ref)?;
                Ok(vec![draft(
                    TaskRunEvent::ContextCommitted {
                        cycle_id,
                        manifest_ref,
                    },
                    Sensitivity::Sensitive,
                )])
            }
            TaskRunCommand::CommitPlan {
                cycle_id,
                plan_revision_ref,
                input_digest,
                output_digest,
                expected_proposal_indexes,
            } => {
                self.validate_plan_commit(
                    cycle_id,
                    &plan_revision_ref,
                    &expected_proposal_indexes,
                )?;
                Ok(vec![draft(
                    TaskRunEvent::PlanCommitted {
                        cycle_id,
                        plan_revision_ref,
                        input_digest,
                        output_digest,
                        expected_proposal_indexes,
                    },
                    Sensitivity::Sensitive,
                )])
            }
            TaskRunCommand::RecordStepOutcome { cycle_id, outcome } => {
                self.validate_step_outcome(cycle_id, &outcome)?;
                Ok(vec![draft(
                    TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome },
                    Sensitivity::Sensitive,
                )])
            }
            TaskRunCommand::CompleteLoopCycle {
                cycle_id,
                disposition,
            } => {
                let attempt_id = self.validate_cycle_completion(cycle_id, &disposition)?;
                let completed = draft(
                    TaskRunEvent::LoopCycleCompleted {
                        cycle_id,
                        attempt_id,
                        disposition: disposition.clone(),
                    },
                    Sensitivity::Sensitive,
                );
                match disposition {
                    LoopDisposition::Continue => Ok(vec![completed]),
                    LoopDisposition::Wait { .. } => Ok(vec![
                        completed,
                        draft(TaskRunEvent::WaitStarted, Sensitivity::Public),
                    ]),
                    LoopDisposition::Complete { .. } => Ok(vec![
                        completed,
                        draft(
                            TaskRunEvent::TaskRunCompleted {
                                result: TerminalResult::Success,
                            },
                            Sensitivity::Public,
                        ),
                    ]),
                    LoopDisposition::Fail { reason, .. } => Ok(vec![
                        completed,
                        draft(
                            TaskRunEvent::TaskRunFailed { reason },
                            Sensitivity::Sensitive,
                        ),
                    ]),
                }
            }
            TaskRunCommand::CreateNextCycle {
                parent_cycle_id,
                successor_cycle_id,
            } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::NextCycleCreated)?;
                let completed = self.validate_successor(parent_cycle_id, successor_cycle_id)?;
                let sequence = completed.sequence.checked_add(1).ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::SuccessorReservationMismatch)
                })?;
                Ok(vec![draft(
                    TaskRunEvent::NextCycleCreated {
                        parent_cycle_id,
                        successor_cycle_id,
                        attempt_id: completed.attempt_id,
                        sequence,
                    },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::ResumeLoopWait { wake_evidence_ref } => {
                self.require_state(TaskRunState::Waiting, TaskRunEventKind::LoopWakeAccepted)?;
                self.validate_wake_evidence(&wake_evidence_ref)?;
                Ok(vec![
                    draft(TaskRunEvent::Resumed, Sensitivity::Public),
                    draft(
                        TaskRunEvent::LoopWakeAccepted {
                            cycle_id: wake_evidence_ref.cycle_id,
                            wake_evidence_ref,
                        },
                        Sensitivity::Sensitive,
                    ),
                ])
            },
            _ => unreachable!("loop command dispatched to wrong handler"),
        }
    }
}
