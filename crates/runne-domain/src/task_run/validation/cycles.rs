impl TaskRun {
    pub(super) fn active_cycle_for(
        &self,
        cycle_id: CycleId,
        state: LoopCycleState,
    ) -> Result<&ActiveLoopCycle, DomainError> {
        let cycle = self
            .active_cycle
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
        if cycle.cycle_id != cycle_id {
            return Err(Self::loop_error(
                LoopInvariantViolation::CycleBindingMismatch,
            ));
        }
        if cycle.state != state {
            return Err(Self::loop_error(LoopInvariantViolation::CycleStateMismatch));
        }
        Ok(cycle)
    }

    pub(super) fn validate_context_commit(
        &self,
        cycle_id: CycleId,
        manifest_ref: &ContextManifestRef,
    ) -> Result<(), DomainError> {
        self.require_state(TaskRunState::Running, TaskRunEventKind::ContextCommitted)?;
        let cycle = self.active_cycle_for(cycle_id, LoopCycleState::Observing)?;
        if manifest_ref.taskrun_id != self.id
            || manifest_ref.attempt_id != cycle.attempt_id
            || manifest_ref.cycle_id != cycle_id
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::ContextBindingMismatch,
            ));
        }
        Ok(())
    }

    pub(super) fn indexes_are_canonical(indexes: &[u32]) -> bool {
        indexes.windows(2).all(|pair| pair[0] < pair[1])
    }

    pub(super) fn validate_plan_commit(
        &self,
        cycle_id: CycleId,
        plan_ref: &PlanRevisionRef,
        expected_indexes: &[u32],
    ) -> Result<(), DomainError> {
        self.require_state(TaskRunState::Running, TaskRunEventKind::PlanCommitted)?;
        let cycle = self
            .active_cycle
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
        if cycle.cycle_id != cycle_id {
            return Err(Self::loop_error(
                LoopInvariantViolation::CycleBindingMismatch,
            ));
        }
        if cycle.state != LoopCycleState::Proposing {
            let previous = cycle
                .plan_revision_ref
                .as_ref()
                .ok_or_else(|| Self::loop_error(LoopInvariantViolation::PlanBindingMismatch))?;
            let parent = crate::plan::PlanParentRef {
                plan_id: previous.plan_id,
                revision: previous.revision,
                integrity_digest: previous.integrity_digest,
            };
            if cycle.state != LoopCycleState::Evaluating
                || plan_ref.parent_ref.as_ref() != Some(&parent)
                || plan_ref.plan_id != previous.plan_id
                || previous.revision.checked_add(1) != Some(plan_ref.revision)
                || plan_ref.planning_policy_ref != previous.planning_policy_ref
                || plan_ref.planning_budget_ref != previous.planning_budget_ref
                || expected_indexes.len() != previous.expected_proposal_indexes.len() + 1
                || !expected_indexes.starts_with(&previous.expected_proposal_indexes)
                || expected_indexes.last().copied()
                    != Some(
                        previous
                            .expected_proposal_indexes
                            .last()
                            .map_or(0, |n| n.saturating_add(1)),
                    )
                || cycle.recorded_outcomes.len() != previous.expected_proposal_indexes.len()
            {
                return Err(Self::loop_error(
                    LoopInvariantViolation::PlanBindingMismatch,
                ));
            }
        }
        let context_ref = cycle
            .context_manifest_ref
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::ContextBindingMismatch))?;
        if !Self::indexes_are_canonical(expected_indexes) {
            return Err(Self::loop_error(
                LoopInvariantViolation::ProposalIndexesNotCanonical,
            ));
        }
        if plan_ref.taskrun_id != self.id
            || plan_ref.cycle_id != cycle_id
            || &plan_ref.context_manifest_ref != context_ref
            || plan_ref.expected_proposal_indexes != expected_indexes
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::PlanBindingMismatch,
            ));
        }
        Ok(())
    }

    pub(super) fn outcome_cardinality_is_valid(outcome: &StepOutcomeRecord) -> bool {
        match outcome.outcome_type {
            StepOutcomeType::Succeeded => outcome.result_ref.is_some(),
            StepOutcomeType::FailedBeforeCommit | StepOutcomeType::Cancelled => {
                outcome.effect_id.is_none()
            }
            StepOutcomeType::FailedAfterCommit | StepOutcomeType::Uncertain => {
                outcome.effect_id.is_some()
            }
        }
    }

    pub(super) fn validate_step_outcome(
        &self,
        cycle_id: CycleId,
        outcome: &StepOutcomeRecord,
    ) -> Result<(), DomainError> {
        self.require_state(TaskRunState::Running, TaskRunEventKind::StepOutcomeRecorded)?;
        let cycle = self.active_cycle_for(cycle_id, LoopCycleState::Acting)?;
        if !cycle
            .expected_proposal_indexes
            .contains(&outcome.proposal_index)
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::ProposalIndexUnexpected,
            ));
        }
        if cycle
            .recorded_outcomes
            .iter()
            .any(|recorded| recorded.proposal_index == outcome.proposal_index)
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::ProposalOutcomeDuplicate,
            ));
        }
        if cycle
            .recorded_outcomes
            .iter()
            .any(|recorded| recorded.step_id == outcome.step_id)
        {
            return Err(Self::loop_error(LoopInvariantViolation::StepIdDuplicate));
        }
        if !Self::outcome_cardinality_is_valid(outcome) {
            return Err(Self::loop_error(
                LoopInvariantViolation::OutcomeCardinalityMismatch,
            ));
        }
        Ok(())
    }

    pub(super) fn validate_cycle_completion(
        &self,
        cycle_id: CycleId,
        disposition: &LoopDisposition,
    ) -> Result<AttemptId, DomainError> {
        self.require_state(TaskRunState::Running, TaskRunEventKind::LoopCycleCompleted)?;
        let cycle = self
            .active_cycle
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
        if cycle.cycle_id != cycle_id {
            return Err(Self::loop_error(
                LoopInvariantViolation::CycleBindingMismatch,
            ));
        }

        match disposition {
            LoopDisposition::Fail {
                unresolved_proposals,
                ..
            } => {
                if !matches!(
                    cycle.state,
                    LoopCycleState::Acting | LoopCycleState::Evaluating
                ) {
                    return Err(Self::loop_error(LoopInvariantViolation::CycleStateMismatch));
                }
                let canonical = cycle
                    .expected_proposal_indexes
                    .iter()
                    .copied()
                    .filter(|index| {
                        !cycle
                            .recorded_outcomes
                            .iter()
                            .any(|outcome| outcome.proposal_index == *index)
                    })
                    .collect::<Vec<_>>();
                if unresolved_proposals != &canonical {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::UnresolvedProposalMismatch,
                    ));
                }
            }
            LoopDisposition::Complete {
                plan_evaluation_ref,
            } => {
                if cycle.state != LoopCycleState::Evaluating {
                    return Err(Self::loop_error(LoopInvariantViolation::CycleStateMismatch));
                }
                let plan_ref = cycle
                    .plan_revision_ref
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::PlanBindingMismatch))?;
                if plan_evaluation_ref.taskrun_id != self.id
                    || plan_evaluation_ref.plan_id != plan_ref.plan_id
                    || plan_evaluation_ref.plan_revision != plan_ref.revision
                    || plan_evaluation_ref.result != PlanEvaluationResult::Passed
                {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PlanBindingMismatch,
                    ));
                }
            }
            LoopDisposition::Continue | LoopDisposition::Wait { .. } => {
                if cycle.state != LoopCycleState::Evaluating {
                    return Err(Self::loop_error(LoopInvariantViolation::CycleStateMismatch));
                }
            }
        }
        Ok(cycle.attempt_id)
    }

    pub(super) fn validate_successor(
        &self,
        parent_cycle_id: CycleId,
        successor_cycle_id: CycleId,
    ) -> Result<&CompletedCycleRef, DomainError> {
        if self.active_cycle.is_some() {
            return Err(Self::loop_error(LoopInvariantViolation::ActiveCycleExists));
        }
        if self.pending_successor.is_some() {
            return Err(Self::loop_error(
                LoopInvariantViolation::SuccessorAlreadyAllocated,
            ));
        }
        if self
            .cycle_history
            .iter()
            .any(|entry| entry.cycle_id == successor_cycle_id)
        {
            return Err(Self::loop_error(LoopInvariantViolation::CycleAlreadyUsed));
        }
        let completed = self
            .last_completed_cycle
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingCompletedCycle))?;
        if completed.cycle_id != parent_cycle_id {
            return Err(Self::loop_error(
                LoopInvariantViolation::CycleBindingMismatch,
            ));
        }
        if completed.successor_allocated {
            return Err(Self::loop_error(
                LoopInvariantViolation::SuccessorAlreadyAllocated,
            ));
        }
        let allowed = match &completed.disposition {
            LoopDisposition::Continue => completed.accepted_wake_evidence.is_none(),
            LoopDisposition::Wait { wake_condition, .. } => completed
                .accepted_wake_evidence
                .as_ref()
                .is_some_and(|evidence| {
                    evidence.cycle_id == completed.cycle_id
                        && evidence.condition_digest == wake_condition.condition_digest
                }),
            LoopDisposition::Complete { .. } | LoopDisposition::Fail { .. } => false,
        };
        if !allowed {
            return Err(Self::loop_error(
                LoopInvariantViolation::SuccessorNotAllowed,
            ));
        }
        Ok(completed)
    }
}
