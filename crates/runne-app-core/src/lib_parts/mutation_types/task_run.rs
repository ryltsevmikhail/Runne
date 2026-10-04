impl MutationRequest {
    /// Creates an AppCore-owned normalized `TaskRun` cancellation request.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid target, zero expected version, or
    /// command identity.
    pub fn cancel_task_run(
        task_run_id: CanonicalId,
        expected_version: u64,
    ) -> Result<Self, AppCoreError> {
        Self::new(
            runne_local_store::MutationOperation::TaskRunCancel,
            runne_local_store::MutationTargetKind::TaskRun,
            task_run_id,
            expected_version,
            CanonicalMutationCommand::CancelTaskRun { task_run_id },
        )
    }

    /// Creates an explicitly acknowledged unknown-outcome successor mutation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid target, zero expected version, or
    /// command identity.
    pub fn supersede_unknown_task_run(
        predecessor_task_run_id: CanonicalId,
        expected_version: u64,
        _acknowledgment: runne_runtime_client::UnknownSuccessorAcknowledgment,
    ) -> Result<Self, AppCoreError> {
        Self::new(
            runne_local_store::MutationOperation::TaskRunUnknownSuccessor,
            runne_local_store::MutationTargetKind::TaskRun,
            predecessor_task_run_id,
            expected_version,
            CanonicalMutationCommand::SupersedeUnknownTaskRun {
                predecessor_task_run_id,
            },
        )
    }
}
