impl TaskRun {
    // ── private helpers ──────────────────────────────────────────────────

    /// Require that the aggregate is in a specific state.
    pub(super) fn require_state(
        &self,
        expected: TaskRunState,
        event_kind: TaskRunEventKind,
    ) -> Result<(), DomainError> {
        if self.state != expected {
            return Err(DomainError::InvalidTransition {
                from: self.state,
                event: event_kind,
            });
        }
        Ok(())
    }

    /// Check that an attempt ID has not been used before.
    pub(super) fn check_attempt_id_unique(
        &self,
        attempt_id: &AttemptId,
    ) -> Result<(), DomainError> {
        if self.attempt_history.contains(attempt_id) {
            return Err(DomainError::DuplicateAttemptId {
                taskrun_id: self.id,
                attempt_id: *attempt_id,
            });
        }
        Ok(())
    }

    pub(super) fn loop_error(violation: LoopInvariantViolation) -> DomainError {
        DomainError::LoopInvariantViolation { violation }
    }

}
