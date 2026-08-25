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

    #[allow(clippy::too_many_lines)]
    async fn reconcile_task_run_under_operation<F>(
        &self,
        context: &RuntimeOperationContext,
        task_run_id: CanonicalId,
        mut on_update: F,
    ) -> Result<TaskRunTimelineSnapshot, AppCoreError>
    where
        F: FnMut(TaskRunTimelineUpdate),
    {
        self.require_current_operation_context(context)?;
        let secure = self.task_run_secure()?;
        let authoritative = context
            .client
            .get_task_run(task_run_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let scope_key = context.identity.task_run_scope(task_run_id);
        if self.resync_required_for_scope(&scope_key)? {
            return Ok(task_run_snapshot(
                task_run_id,
                &authoritative,
                0,
                0,
                Vec::new(),
                TaskRunRecoveryDisposition::ResyncRequired,
            ));
        }
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        if self.task_run_has_authenticated_resync_marker(secure, &scope_key, &task_run_id)? {
            self.set_resync_required_for_scope(scope_key)?;
            return Ok(task_run_snapshot(
                task_run_id,
                &authoritative,
                0,
                0,
                Vec::new(),
                TaskRunRecoveryDisposition::ResyncRequired,
            ));
        }
        let checkpoint = {
            let mut store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            replay::task_run::checkpoint(&mut store, secure, &scope_key)
        };
        let checkpoint = match checkpoint {
            Ok(value) => value,
            Err(error) => {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(error);
            }
        };
        let mut local_error = None;
        let replay_scope = ReplayScope::new(ReplayAggregateKind::TaskRun, task_run_id);
        let result = context
            .client
            .catch_up_from_persisted_cursor(
                replay_scope,
                checkpoint.as_ref().map(|value| value.cursor.as_str()),
                ReplayIdentityTracker::new(),
                |delivery| {
                    let Ok(mut store) = self.store.lock() else {
                        local_error = Some(AppCoreError::StateUnavailable);
                        return Err(());
                    };
                    match replay::task_run::apply_delivery(
                        &mut store,
                        secure,
                        &scope_key,
                        &context.identity,
                        &task_run_id.to_string(),
                        delivery,
                    ) {
                        Ok(update) => Ok(update),
                        Err(error) => {
                            local_error = Some(error);
                            Err(())
                        }
                    }
                },
                |update| {
                    if let Some(update) = update {
                        on_update(update);
                    }
                },
            )
            .await;
        if let Err(error) = result {
            if let Some(error) = local_error {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(error);
            }
            if let Some(baseline) = error.retention_baseline_v2() {
                self.promote_retention_baseline_v2_under_operation(
                    context,
                    replay_scope,
                    &scope_key,
                    checkpoint.as_ref(),
                    baseline,
                )
                .await?;
                self.set_resync_required_for_scope(scope_key)?;
                return Ok(task_run_snapshot(
                    task_run_id,
                    &authoritative,
                    0,
                    0,
                    Vec::new(),
                    TaskRunRecoveryDisposition::ResyncRequired,
                ));
            }
            return Err(self.map_replay_failure(&error, &scope_key));
        }
        self.require_current_operation_context(context)?;
        let persisted = {
            let mut store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            replay::task_run::snapshot(&mut store, secure, &scope_key, &task_run_id.to_string())?
        };
        let (revision, stream, entries) = match persisted {
            replay::task_run::TaskRunProjection::Missing => (0, 0, Vec::new()),
            replay::task_run::TaskRunProjection::Decoded(value) => (
                value.projection_revision,
                value.stream_version,
                value.entries,
            ),
            replay::task_run::TaskRunProjection::AuthenticatedOpaque {
                revision,
                stream_version,
            } => {
                self.set_resync_required_for_scope(scope_key)?;
                return Ok(task_run_snapshot(
                    task_run_id,
                    &authoritative,
                    revision,
                    stream_version,
                    Vec::new(),
                    TaskRunRecoveryDisposition::ResyncRequired,
                ));
            }
        };
        self.transition_runtime(RuntimeAvailability::Live)?;
        Ok(task_run_snapshot(
            task_run_id,
            &authoritative,
            revision,
            stream,
            entries,
            TaskRunRecoveryDisposition::Live,
        ))
    }
}

impl AppCore {
    fn task_run_has_authenticated_resync_marker(
        &self,
        secure: &dyn runne_secure_store::SecureStore,
        scope: &ReplayScopeKey,
        task_run_id: &CanonicalId,
    ) -> Result<bool, AppCoreError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        Ok(matches!(
            replay::task_run::snapshot(&mut store, secure, scope, &task_run_id.to_string())?,
            replay::task_run::TaskRunProjection::AuthenticatedOpaque { .. }
        ))
    }
}

fn task_run_snapshot(
    task_run_id: CanonicalId,
    authoritative: &runne_runtime_client::TaskRunSnapshot,
    projection_revision: u64,
    replay_stream_version: u64,
    entries: Vec<TaskRunTimelineEntry>,
    recovery: TaskRunRecoveryDisposition,
) -> TaskRunTimelineSnapshot {
    TaskRunTimelineSnapshot {
        task_run_id: task_run_id.to_string(),
        projection_revision,
        stream_version: authoritative.stream_version().max(replay_stream_version),
        state: task_run_state(authoritative.state()),
        active_attempt_id: authoritative
            .active_attempt_id()
            .map(|value| value.to_string()),
        terminal: task_run_terminal(authoritative.state()),
        entries,
        recovery,
    }
}

include!("task_run/projection.rs");
