impl AppCore {
    /// Reads the authoritative runtime `TaskRun` list for native lifecycle gates.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the authenticated runtime list is unavailable.
    pub async fn active_task_run_count(&self) -> Result<u64, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.task_run_read_context()?;
        let snapshots = context
            .client
            .list_task_runs()
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        Ok(snapshots
            .into_iter()
            .filter(|snapshot| {
                matches!(
                    snapshot.state(),
                    TaskRunState::Running
                        | TaskRunState::Waiting
                        | TaskRunState::Retrying
                        | TaskRunState::Checkpointing
                        | TaskRunState::Cancelling
                        | TaskRunState::Reconciling
                )
            })
            .count() as u64)
    }
}
