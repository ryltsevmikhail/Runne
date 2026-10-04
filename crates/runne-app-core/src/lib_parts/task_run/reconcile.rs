enum TaskRunCatchUp {
    Applied,
    ResyncRequired,
}

impl AppCore {
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
            return Ok(task_run_resync_snapshot(task_run_id, &authoritative));
        }
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        if self.task_run_has_authenticated_resync_marker(secure, &scope_key, &task_run_id)? {
            self.set_resync_required_for_scope(scope_key.clone())?;
            return Ok(task_run_resync_snapshot(task_run_id, &authoritative));
        }
        let checkpoint = match self.task_run_checkpoint(secure, &scope_key) {
            Ok(value) => value,
            Err(error) => {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(error);
            }
        };
        if matches!(
            self.catch_up_task_run(
                context,
                secure,
                &scope_key,
                task_run_id,
                checkpoint.as_ref(),
                &mut on_update,
            )
            .await?,
            TaskRunCatchUp::ResyncRequired
        ) {
            return Ok(task_run_resync_snapshot(task_run_id, &authoritative));
        }
        self.task_run_persisted_snapshot(context, secure, &scope_key, task_run_id, &authoritative)
            .await
    }

    async fn catch_up_task_run<F>(
        &self,
        context: &RuntimeOperationContext,
        secure: &dyn SecureStore,
        scope_key: &ReplayScopeKey,
        task_run_id: CanonicalId,
        checkpoint: Option<&runne_local_store::ReplayCheckpoint>,
        on_update: &mut F,
    ) -> Result<TaskRunCatchUp, AppCoreError>
    where
        F: FnMut(TaskRunTimelineUpdate),
    {
        let replay_scope = ReplayScope::new(ReplayAggregateKind::TaskRun, task_run_id);
        let mut local_error = None;
        let result = context
            .client
            .catch_up_from_persisted_cursor(
                replay_scope,
                checkpoint.map(|value| value.cursor.as_str()),
                ReplayIdentityTracker::new(),
                |delivery| match self.apply_task_run_delivery(
                    secure,
                    scope_key,
                    context,
                    task_run_id,
                    delivery,
                ) {
                    Ok(update) => Ok(update),
                    Err(error) => {
                        local_error = Some(error);
                        Err(())
                    }
                },
                |update| {
                    if let Some(update) = update {
                        on_update(update);
                    }
                },
            )
            .await;
        let Err(error) = result else {
            return Ok(TaskRunCatchUp::Applied);
        };
        if let Some(error) = local_error {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(error);
        }
        if let Some(baseline) = error.retention_baseline_v2() {
            self.promote_retention_baseline_v2_under_operation(
                context,
                replay_scope,
                scope_key,
                checkpoint,
                baseline,
            )
            .await?;
            self.set_resync_required_for_scope(scope_key.clone())?;
            return Ok(TaskRunCatchUp::ResyncRequired);
        }
        Err(self.map_replay_failure(&error, scope_key))
    }

    fn apply_task_run_delivery(
        &self,
        secure: &dyn SecureStore,
        scope_key: &ReplayScopeKey,
        context: &RuntimeOperationContext,
        task_run_id: CanonicalId,
        delivery: &runne_runtime_client::ReplayDelivery,
    ) -> Result<Option<TaskRunTimelineUpdate>, AppCoreError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        replay::task_run::apply_delivery(
            &mut store,
            secure,
            scope_key,
            &context.identity,
            &task_run_id.to_string(),
            delivery,
        )
    }

    fn task_run_checkpoint(
        &self,
        secure: &dyn SecureStore,
        scope_key: &ReplayScopeKey,
    ) -> Result<Option<runne_local_store::ReplayCheckpoint>, AppCoreError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        replay::task_run::checkpoint(&mut store, secure, scope_key)
    }

    async fn task_run_persisted_snapshot(
        &self,
        context: &RuntimeOperationContext,
        secure: &dyn SecureStore,
        scope_key: &ReplayScopeKey,
        task_run_id: CanonicalId,
        initial_authoritative: &runne_runtime_client::TaskRunSnapshot,
    ) -> Result<TaskRunTimelineSnapshot, AppCoreError> {
        self.require_current_operation_context(context)?;
        let persisted = {
            let mut store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            replay::task_run::snapshot(&mut store, secure, scope_key, &task_run_id.to_string())?
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
                self.set_resync_required_for_scope(scope_key.clone())?;
                return Ok(task_run_snapshot(
                    task_run_id,
                    initial_authoritative,
                    revision,
                    stream_version,
                    Vec::new(),
                    TaskRunRecoveryDisposition::ResyncRequired,
                ));
            }
        };
        let authoritative = context
            .client
            .get_task_run(task_run_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        self.require_current_operation_context(context)?;
        ensure_authoritative_task_run_covers_replay(authoritative.stream_version(), stream)?;
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

    fn task_run_has_authenticated_resync_marker(
        &self,
        secure: &dyn SecureStore,
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

const fn ensure_authoritative_task_run_covers_replay(
    authoritative_version: u64,
    replay_version: u64,
) -> Result<(), AppCoreError> {
    if authoritative_version < replay_version {
        return Err(AppCoreError::RuntimeUnavailable);
    }
    Ok(())
}

fn task_run_resync_snapshot(
    task_run_id: CanonicalId,
    authoritative: &runne_runtime_client::TaskRunSnapshot,
) -> TaskRunTimelineSnapshot {
    task_run_snapshot(
        task_run_id,
        authoritative,
        0,
        0,
        Vec::new(),
        TaskRunRecoveryDisposition::ResyncRequired,
    )
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
        terminal: task_run_terminal(authoritative.state(), authoritative.terminal_result()),
        entries,
        recovery,
    }
}
