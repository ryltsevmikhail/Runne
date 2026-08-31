impl AppCore {
    /// Requests durable cancellation through the anchored mutation ledger.
    ///
    /// # Errors
    ///
    /// Returns an error when the ID, mutation anchor, runtime response, or
    /// authoritative acknowledgement is invalid.
    pub async fn cancel_task_run(
        &self,
        task_run_id: &str,
        expected_version: u64,
    ) -> Result<runne_runtime_client::TaskRunCancellationAcknowledgement, AppCoreError> {
        let task_run_id =
            CanonicalId::parse(task_run_id).map_err(|_| AppCoreError::InvalidMutation)?;
        let lease = self
            .prepare_mutation(MutationRequest::cancel_task_run(
                task_run_id,
                expected_version,
            )?)
            .await?;
        match self.dispatch_prepared_mutation(lease).await? {
            MutationDispatchResult::TaskRunCancellationRequested(value) => Ok(value),
            _ => Err(AppCoreError::InvalidMutation),
        }
    }

    /// Queries and durably replays one authoritative `TaskRun` timeline.
    ///
    /// # Errors
    ///
    /// Returns an error when runtime identity, local replay state, or the
    /// authoritative snapshot cannot be validated.
    pub async fn get_task_run_timeline(
        &self,
        task_run_id: &str,
    ) -> Result<TaskRunTimelineSnapshot, AppCoreError> {
        let task_run_id =
            CanonicalId::parse(task_run_id).map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let _operation = self.runtime_operation.lock().await;
        let context = self.task_run_read_context()?;
        self.reconcile_task_run_under_operation(&context, task_run_id, |_| {})
            .await
    }

    /// Performs only an authenticated read/replay recovery for a `TaskRun`.
    ///
    /// # Errors
    ///
    /// Returns an error when resync is not required or recovery evidence is
    /// unavailable or invalid.
    pub async fn resync_task_run_timeline(
        &self,
        task_run_id: &str,
    ) -> Result<TaskRunTimelineSnapshot, AppCoreError> {
        let task_run_id =
            CanonicalId::parse(task_run_id).map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let _operation = self.runtime_operation.lock().await;
        let context = self.task_run_read_context()?;
        let scope = context.identity.task_run_scope(task_run_id);
        if !self.resync_required_for_scope(&scope)? {
            return Err(AppCoreError::ReplayResyncRequired);
        }
        self.clear_resync_scope(&scope)?;
        self.reconcile_task_run_under_operation(&context, task_run_id, |_| {})
            .await
    }

    fn task_run_read_context(&self) -> Result<RuntimeOperationContext, AppCoreError> {
        if matches!(
            self.runtime_availability()?,
            RuntimeAvailability::Fatal
                | RuntimeAvailability::Incompatible
                | RuntimeAvailability::Revoked
        ) {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.runtime_operation_context()
    }

    fn task_run_secure(&self) -> Result<&dyn runne_secure_store::SecureStore, AppCoreError> {
        self.mutation_security
            .as_ref()
            .map(|value| value.secure.as_ref())
            .ok_or(AppCoreError::MutationUnavailable)
    }
}

include!("task_run/reconcile.rs");
include!("task_run/projection.rs");
