impl AppCore {
    /// Retains the authenticated live replay session until cancellation or a
    /// closed recovery disposition; no renderer action can advance the cursor.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime, authenticated replay state, or live
    /// recovery disposition cannot be validated.
    ///
    /// # Panics
    ///
    /// Does not panic for a valid runtime-client error; the retained baseline
    /// is unwrapped only after checking that it is present.
    #[allow(clippy::too_many_lines)]
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
            let operation = self.runtime_operation.lock().await;
            let context = self.task_run_read_context()?;
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
            let checkpoint = {
                let mut store = self
                    .store
                    .lock()
                    .map_err(|_| AppCoreError::StateUnavailable)?;
                replay::task_run::checkpoint(&mut store, secure, &scope_key)?
            };
            let mut local_error = None;
            let replay_scope = ReplayScope::new(ReplayAggregateKind::TaskRun, task_run_id);
            let live_result = context
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
            let mut live = match live_result {
                Ok(live) => live,
                Err(_) if local_error.is_some() => {
                    self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                    return Err(local_error
                        .take()
                        .unwrap_or(AppCoreError::LocalProjectionUnavailable));
                }
                Err(error) if error.retention_baseline_v2().is_some() => {
                    self.promote_retention_baseline_v2_under_operation(
                        &context,
                        replay_scope,
                        &scope_key,
                        checkpoint.as_ref(),
                        error.retention_baseline_v2().expect("checked"),
                    )
                    .await?;
                    self.set_resync_required_for_scope(scope_key)?;
                    return Err(AppCoreError::ReplayResyncRequired);
                }
                Err(error)
                    if error.recovery_disposition() == ReplayRecoveryDisposition::Reconnectable =>
                {
                    self.set_runtime_failure(RuntimeAvailability::Reconnecting)?;
                    let delay = match reconnect_policy.record_failure() {
                        ReconnectDecision::RetryAfter(delay) => delay,
                        ReconnectDecision::Exhausted => {
                            return Err(AppCoreError::RuntimeUnavailable);
                        }
                    };
                    drop(operation);
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(error) => return Err(self.map_replay_failure(&error, &scope_key)),
            };
            self.transition_runtime(RuntimeAvailability::Live)?;
            drop(operation);
            let live_started = Instant::now();
            let recovery = loop {
                let event = match live.next_event().await {
                    Ok(event) => event,
                    Err(error) => break error.recovery_disposition(),
                };
                let _operation = self.runtime_operation.lock().await;
                if self.require_current_operation_context(&context).is_err() {
                    return Err(AppCoreError::RuntimeUnavailable);
                }
                match event {
                    ReplayStreamEvent::Heartbeat => {}
                    ReplayStreamEvent::Terminal(terminal) => break terminal.recovery_disposition(),
                    ReplayStreamEvent::Delivery(delivery) => {
                        let update = {
                            let mut store = self
                                .store
                                .lock()
                                .map_err(|_| AppCoreError::StateUnavailable)?;
                            replay::task_run::apply_delivery(
                                &mut store,
                                secure,
                                &scope_key,
                                &context.identity,
                                &task_run_id.to_string(),
                                &delivery,
                            )
                        };
                        let update = match update {
                            Ok(update) => update,
                            Err(error) => {
                                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                                return Err(error);
                            }
                        };
                        if let Err(error) = live.acknowledge(&delivery).await {
                            break error.recovery_disposition();
                        }
                        if let Some(update) = update {
                            on_update(update);
                        }
                        reconnect_policy.record_live_delivery(live_started.elapsed());
                    }
                }
            };
            let operation = self.runtime_operation.lock().await;
            if recovery != ReplayRecoveryDisposition::Reconnectable {
                return Err(self.map_recovery_failure(recovery, &scope_key));
            }
            self.set_runtime_failure(RuntimeAvailability::Reconnecting)?;
            let delay = match reconnect_policy.record_failure() {
                ReconnectDecision::RetryAfter(delay) => delay,
                ReconnectDecision::Exhausted => return Err(AppCoreError::RuntimeUnavailable),
            };
            drop(operation);
            tokio::time::sleep(delay).await;
        }
    }
}
