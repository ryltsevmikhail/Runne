impl TaskRun {
    pub(super) fn validate_wake_evidence(
        &self,
        wake_evidence_ref: &WakeEvidenceRef,
    ) -> Result<(), DomainError> {
        let pending = self
            .pending_loop_wait
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::WakeEvidenceMismatch))?;
        if wake_evidence_ref.cycle_id != pending.cycle_id
            || wake_evidence_ref.condition_digest != pending.wake_condition.condition_digest
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::WakeEvidenceMismatch,
            ));
        }
        Ok(())
    }

    pub(super) fn validate_recovery_ref(
        &self,
        reconciliation_ref: &ReconciliationResultRef,
    ) -> Result<(), DomainError> {
        let active_attempt = self
            .active_attempt
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveAttempt))?;
        if reconciliation_ref.taskrun_id != self.id
            || reconciliation_ref.predecessor_attempt_id != active_attempt
            || reconciliation_ref.recovery_generation != self.recovery_generation
            || reconciliation_ref.status != ReconciliationStatus::Reconciled
            || reconciliation_ref.unresolved_effect_count != 0
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::RecoveryReferenceMismatch,
            ));
        }
        Ok(())
    }

    pub(super) fn validate_checkpoint_body(
        &self,
        body: &LoopCheckpointBody,
    ) -> Result<(), DomainError> {
        let active_attempt = self
            .active_attempt
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveAttempt))?;
        let active_cycle = self
            .active_cycle
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
        if body.cycle_id != active_cycle.cycle_id
            || body.attempt_id != active_attempt
            || body.plan_revision_ref.as_ref() != active_cycle.plan_revision_ref.as_ref()
            || body.context_manifest_ref.as_ref() != active_cycle.context_manifest_ref.as_ref()
        {
            return Err(Self::loop_error(LoopInvariantViolation::CheckpointMismatch));
        }
        Ok(())
    }
}
