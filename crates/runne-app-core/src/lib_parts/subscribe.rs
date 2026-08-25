#[allow(clippy::too_many_lines)]
impl AppCore {
    /// Reconciles from the durable checkpoint and then emits acknowledged live
    /// Conversation updates until the stream terminates or the caller cancels
    /// the future.
    ///
    /// # Errors
    ///
    /// Returns a closed replay/runne-local-store failure without exposing replay
    /// cursors or runtime credentials.
    #[allow(clippy::too_many_lines)]
    pub async fn subscribe_project_conversation<F>(
        &self,
        project_id: i64,
        on_update: F,
    ) -> Result<(), AppCoreError>
    where
        F: FnMut(ConversationTimelineUpdate) + Send,
    {
        self.subscribe_conversation(ConversationReferenceOwner::Project(project_id), on_update)
            .await
    }

    /// Reconciles and streams one canonical Workspace Conversation.
    ///
    /// # Errors
    ///
    /// Returns a closed local, replay, or runtime failure.
    pub async fn subscribe_workspace_conversation<F>(
        &self,
        workspace_id: &str,
        on_update: F,
    ) -> Result<(), AppCoreError>
    where
        F: FnMut(ConversationTimelineUpdate) + Send,
    {
        let workspace_id = CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        self.subscribe_conversation(ConversationReferenceOwner::Workspace(workspace_id), on_update)
            .await
    }

    async fn subscribe_conversation<F>(
        &self,
        owner: ConversationReferenceOwner,
        mut on_update: F,
    ) -> Result<(), AppCoreError>
    where
        F: FnMut(ConversationTimelineUpdate) + Send,
    {
        let mut reconnect_policy = ReconnectPolicy::new();
        loop {
            let operation = self.runtime_operation.lock().await;
            let context = self.runtime_operation_context()?;
            if !matches!(
                self.runtime_availability()?,
                RuntimeAvailability::Live | RuntimeAvailability::Reconnecting
            ) || self.require_current_operation_context(&context).is_err()
            {
                return Err(AppCoreError::RuntimeUnavailable);
            }
            let reference = match owner {
                ConversationReferenceOwner::Project(project_id) => {
                    self.load_or_prepare_conversation_reference(project_id)?
                }
                ConversationReferenceOwner::Workspace(workspace_id) => {
                    self.load_workspace_conversation_reference(&workspace_id.to_string())?
                }
            };
            let Some(bound) = reference.bound() else {
                return Err(AppCoreError::InvalidConversationReference);
            };
            if !context.identity.matches_reference(bound) {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(AppCoreError::RuntimeIdentityConflict);
            }
            self.transition_runtime(RuntimeAvailability::Reconciling)?;
            let scope_key = context.identity.scope(&reference);
            let checkpoint = {
                let mut store = self
                    .store
                    .lock()
                    .map_err(|_| AppCoreError::StateUnavailable)?;
                match replay::checkpoint(
                    &mut store,
                    self.mutation_security
                        .as_ref()
                        .map(|value| value.secure.as_ref()),
                    &scope_key,
                ) {
                    Ok(checkpoint) => checkpoint,
                    Err(error) => {
                        self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                        return Err(error);
                    }
                }
            };
            let replay_scope = ReplayScope::new(
                ReplayAggregateKind::Conversation,
                reference.conversation_id(),
            );
            let identities = ReplayIdentityTracker::new();
            let mut local_error = None;
            let live_result = context
                .client
                .catch_up_from_persisted_cursor(
                    replay_scope,
                    checkpoint.as_ref().map(|value| value.cursor.as_str()),
                    identities,
                    |delivery| {
                        let Ok(mut store) = self.store.lock() else {
                            local_error = Some(AppCoreError::StateUnavailable);
                            return Err(());
                        };
                        match replay::apply_delivery(
                            &mut store,
                            self.mutation_security.as_ref().map(|value| value.secure.as_ref()),
                            &reference,
                            &context.identity,
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
                Err(error) => {
                    if error.recovery_disposition() != ReplayRecoveryDisposition::Reconnectable {
                        return Err(self.map_replay_failure(&error, &scope_key));
                    }
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
                    ReplayStreamEvent::Terminal(terminal) => {
                        break terminal.recovery_disposition();
                    }
                    ReplayStreamEvent::Delivery(delivery) => {
                        let update_result = {
                            let mut store = self
                                .store
                                .lock()
                                .map_err(|_| AppCoreError::StateUnavailable)?;
                            replay::apply_delivery(
                                &mut store,
                                self.mutation_security.as_ref().map(|value| value.secure.as_ref()),
                                &reference,
                                &context.identity,
                                &delivery,
                            )
                        };
                        let update = match update_result {
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
            if self.require_current_operation_context(&context).is_err() {
                return Err(AppCoreError::RuntimeUnavailable);
            }
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
