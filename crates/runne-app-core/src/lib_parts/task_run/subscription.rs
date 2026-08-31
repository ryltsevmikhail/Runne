struct TaskRunLiveReplay {
    context: RuntimeOperationContext,
    scope_key: ReplayScopeKey,
    live: runne_runtime_client::ReplayLiveSession,
}

enum TaskRunSubscriptionOpening {
    Live(Box<TaskRunLiveReplay>),
    Reconnect(Duration),
}

impl AppCore {
    /// Retains the authenticated live replay session until cancellation or a
    /// closed recovery disposition; no renderer action can advance the cursor.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime, authenticated replay state, or live
    /// recovery disposition cannot be validated.
    pub async fn subscribe_task_run_timeline<F>(
        &self,
        task_run_id: &str,
        mut on_update: F,
    ) -> Result<(), AppCoreError>
    where
        F: FnMut(TaskRunTimelineUpdate) + Send,
    {
        let task_run_id =
            CanonicalId::parse(task_run_id).map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let mut reconnect_policy = ReconnectPolicy::new();
        loop {
            let opening = {
                let _operation = self.runtime_operation.lock().await;
                let context = self.task_run_read_context()?;
                self.open_task_run_live_replay(
                    &context,
                    task_run_id,
                    &mut on_update,
                    &mut reconnect_policy,
                )
                .await?
            };
            match opening {
                TaskRunSubscriptionOpening::Reconnect(delay) => tokio::time::sleep(delay).await,
                TaskRunSubscriptionOpening::Live(mut live) => {
                    let delay = self
                        .run_task_run_live_replay(
                            &mut live,
                            task_run_id,
                            &mut on_update,
                            &mut reconnect_policy,
                        )
                        .await?;
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    async fn open_task_run_live_replay<F>(
        &self,
        context: &RuntimeOperationContext,
        task_run_id: CanonicalId,
        on_update: &mut F,
        reconnect_policy: &mut ReconnectPolicy,
    ) -> Result<TaskRunSubscriptionOpening, AppCoreError>
    where
        F: FnMut(TaskRunTimelineUpdate),
    {
        self.require_current_operation_context(context)?;
        let secure = self.task_run_secure()?;
        let scope_key = context.identity.task_run_scope(task_run_id);
        if self.resync_required_for_scope(&scope_key)? {
            return Err(AppCoreError::ReplayResyncRequired);
        }
        if self.task_run_has_authenticated_resync_marker(secure, &scope_key, &task_run_id)? {
            self.set_resync_required_for_scope(scope_key)?;
            return Err(AppCoreError::ReplayResyncRequired);
        }
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        let checkpoint = self.task_run_checkpoint(secure, &scope_key)?;
        let replay_scope = ReplayScope::new(ReplayAggregateKind::TaskRun, task_run_id);
        let mut local_error = None;
        let live_result = context
            .client
            .catch_up_from_persisted_cursor(
                replay_scope,
                checkpoint.as_ref().map(|value| value.cursor.as_str()),
                ReplayIdentityTracker::new(),
                |delivery| match self.apply_task_run_delivery(
                    secure,
                    &scope_key,
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
        match live_result {
            Ok(live) => {
                self.transition_runtime(RuntimeAvailability::Live)?;
                Ok(TaskRunSubscriptionOpening::Live(Box::new(
                    TaskRunLiveReplay {
                        context: context.clone(),
                        scope_key,
                        live,
                    },
                )))
            }
            Err(_) if local_error.is_some() => {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                Err(local_error.unwrap_or(AppCoreError::LocalProjectionUnavailable))
            }
            Err(error) if error.retention_baseline_v2().is_some() => {
                self.promote_retention_baseline_v2_under_operation(
                    context,
                    replay_scope,
                    &scope_key,
                    checkpoint.as_ref(),
                    error.retention_baseline_v2().expect("checked"),
                )
                .await?;
                self.set_resync_required_for_scope(scope_key)?;
                Err(AppCoreError::ReplayResyncRequired)
            }
            Err(error)
                if error.recovery_disposition() == ReplayRecoveryDisposition::Reconnectable =>
            {
                Ok(TaskRunSubscriptionOpening::Reconnect(
                    self.schedule_task_run_reconnect(reconnect_policy)?,
                ))
            }
            Err(error) => Err(self.map_replay_failure(&error, &scope_key)),
        }
    }

    async fn run_task_run_live_replay<F>(
        &self,
        session: &mut TaskRunLiveReplay,
        task_run_id: CanonicalId,
        on_update: &mut F,
        reconnect_policy: &mut ReconnectPolicy,
    ) -> Result<Duration, AppCoreError>
    where
        F: FnMut(TaskRunTimelineUpdate),
    {
        let secure = self.task_run_secure()?;
        let live_started = Instant::now();
        let recovery = loop {
            let event = match session.live.next_event().await {
                Ok(event) => event,
                Err(error) => break error.recovery_disposition(),
            };
            let _operation = self.runtime_operation.lock().await;
            self.require_current_operation_context(&session.context)?;
            match event {
                ReplayStreamEvent::Heartbeat => {}
                ReplayStreamEvent::Terminal(terminal) => break terminal.recovery_disposition(),
                ReplayStreamEvent::Delivery(delivery) => {
                    let update = self.apply_task_run_delivery(
                        secure,
                        &session.scope_key,
                        &session.context,
                        task_run_id,
                        &delivery,
                    );
                    let update = match update {
                        Ok(update) => update,
                        Err(error) => {
                            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                            return Err(error);
                        }
                    };
                    if let Err(error) = session.live.acknowledge(&delivery).await {
                        break error.recovery_disposition();
                    }
                    if let Some(update) = update {
                        on_update(update);
                    }
                    reconnect_policy.record_live_delivery(live_started.elapsed());
                }
            }
        };
        let _operation = self.runtime_operation.lock().await;
        if recovery != ReplayRecoveryDisposition::Reconnectable {
            return Err(self.map_recovery_failure(recovery, &session.scope_key));
        }
        self.schedule_task_run_reconnect(reconnect_policy)
    }

    fn schedule_task_run_reconnect(
        &self,
        reconnect_policy: &mut ReconnectPolicy,
    ) -> Result<Duration, AppCoreError> {
        self.set_runtime_failure(RuntimeAvailability::Reconnecting)?;
        let delay = match reconnect_policy.record_failure() {
            ReconnectDecision::RetryAfter(delay) => delay,
            ReconnectDecision::Exhausted => return Err(AppCoreError::RuntimeUnavailable),
        };
        Ok(delay)
    }
}
