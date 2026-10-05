impl AppCore {
    /// Submits one runtime-owned `TaskRun` through the authenticated anchored ledger.
    /// The acknowledgement means Created+Queued was durably recorded; it does
    /// not mean that the run was admitted or started.
    ///
    /// # Errors
    ///
    /// Returns an error when input validation, the mutation anchor, runtime
    /// response, or authoritative acknowledgement is invalid or unavailable.
    pub async fn submit_task_run(
        &self,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        prompt: String,
    ) -> Result<runne_runtime_client::TaskRunSubmitAcknowledgement, AppCoreError> {
        let lease = self
            .prepare_mutation(MutationRequest::submit_task_run(
                conversation_id,
                workspace_id,
                prompt,
            )?)
            .await?;
        match self.dispatch_prepared_mutation(lease).await? {
            MutationDispatchResult::TaskRunSubmitted(value) => Ok(value),
            _ => Err(AppCoreError::InvalidMutation),
        }
    }

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

    /// Creates a linked successor after explicit duplicate-execution and cost acknowledgment.
    ///
    /// # Errors
    ///
    /// Returns an error when the ID, expected version, mutation anchor, runtime
    /// response, or authoritative acknowledgement is invalid.
    pub async fn supersede_unknown_task_run(
        &self,
        task_run_id: &str,
        expected_version: u64,
        acknowledgment: runne_runtime_client::UnknownSuccessorAcknowledgment,
    ) -> Result<runne_runtime_client::TaskRunSuccessorAcknowledgement, AppCoreError> {
        let task_run_id =
            CanonicalId::parse(task_run_id).map_err(|_| AppCoreError::InvalidMutation)?;
        let lease = self
            .prepare_mutation(MutationRequest::supersede_unknown_task_run(
                task_run_id,
                expected_version,
                acknowledgment,
            )?)
            .await?;
        match self.dispatch_prepared_mutation(lease).await? {
            MutationDispatchResult::TaskRunUnknownSuccessorCreated(value) => Ok(value),
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

    /// Reads the versioned local and remote effect facts for one `TaskRun`.
    ///
    /// # Errors
    ///
    /// Returns an error when the authenticated runtime is unavailable or its
    /// effect projection is invalid.
    pub async fn get_task_run_effects(
        &self,
        task_run_id: &str,
    ) -> Result<runne_runtime_client::TaskRunEffectsV1, AppCoreError> {
        let task_run_id =
            CanonicalId::parse(task_run_id).map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let _operation = self.runtime_operation.lock().await;
        let context = self.task_run_read_context()?;
        self.require_current_operation_context(&context)?;
        let effects = context
            .client
            .get_task_run_effects(task_run_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        self.require_current_operation_context(&context)?;
        Ok(effects)
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
include!("task_run/managed_types.rs");
include!("task_run/managed.rs");
include!("task_run/managed_recovery.rs");
include!("task_run/managed_intent.rs");
include!("task_run/managed_inventory.rs");
include!("task_run/managed_attention_effects.rs");
include!("task_run/managed_draft.rs");
