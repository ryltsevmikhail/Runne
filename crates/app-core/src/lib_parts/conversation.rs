impl AppCore {
    fn load_or_prepare_conversation_reference(
        &self,
        project_id: i64,
    ) -> Result<StoredConversationReference, AppCoreError> {
        if project_id <= 0 {
            return Err(AppCoreError::ProjectUnavailable);
        }
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        if store.get_project(project_id)?.is_none() {
            return Err(AppCoreError::ProjectUnavailable);
        }
        let key = format!("runtime.conversation.project.{project_id}");
        if let Some(serialized) = store.get_setting(&key)? {
            return parse_conversation_reference(&serialized);
        }
        let command_id = CanonicalId::now_v7();
        let reference = StoredConversationReference::V1(StoredConversationReferenceV1 {
            schema_version: 1,
            conversation_id: CanonicalId::now_v7(),
            workspace_id: CanonicalId::now_v7(),
            create_command_id: command_id,
            idempotency_key: command_id.to_string(),
        });
        let serialized = serde_json::to_string(&reference)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        store.set_setting(&key, &serialized)?;
        drop(store);
        Ok(reference)
    }

    fn bind_conversation_reference(
        &self,
        project_id: i64,
        reference: StoredConversationReference,
        identity: &replay::StableRuntimeIdentity,
    ) -> Result<StoredConversationReference, AppCoreError> {
        if let Some(bound) = reference.bound() {
            if identity.matches_reference(bound) {
                return Ok(reference);
            }
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        let bound = StoredConversationReference::V2(identity.bind_reference(&reference));
        let serialized = serde_json::to_string(&bound)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        store.set_setting(
            &format!("runtime.conversation.project.{project_id}"),
            &serialized,
        )?;
        drop(store);
        Ok(bound)
    }

    async fn reconcile_conversation<F>(
        &self,
        client: &AuthenticatedRuntimeClient,
        reference: &StoredConversationReference,
        identity: &replay::StableRuntimeIdentity,
        mut on_update: F,
    ) -> Result<ConversationSnapshot, AppCoreError>
    where
        F: FnMut(ConversationTimelineUpdate),
    {
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        let scope_key = identity.scope(reference);
        let checkpoint_result = {
            let store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            replay::checkpoint(&store, &scope_key)
        };
        let checkpoint = match checkpoint_result {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(error);
            }
        };
        let scope = ReplayScope::new(
            ReplayAggregateKind::Conversation,
            reference.conversation_id(),
        );
        let mut local_error = None;
        let result = client
            .catch_up_from_persisted_cursor(
                scope,
                checkpoint.as_ref().map(|value| value.cursor.as_str()),
                ReplayIdentityTracker::new(),
                |delivery| {
                    let Ok(mut store) = self.store.lock() else {
                        local_error = Some(AppCoreError::StateUnavailable);
                        return Err(());
                    };
                    match replay::apply_delivery(&mut store, reference, identity, delivery) {
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
            return Err(self.map_replay_failure(&error, &scope_key));
        }
        let snapshot_result = {
            let store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            replay::snapshot(&store, &scope_key, reference)
        };
        let snapshot = match snapshot_result {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(error);
            }
        };
        self.transition_runtime(RuntimeAvailability::Live)?;
        Ok(snapshot)
    }

    fn map_replay_failure(
        &self,
        error: &ReplayClientError,
        scope_key: &ReplayScopeKey,
    ) -> AppCoreError {
        self.map_recovery_failure(error.recovery_disposition(), scope_key)
    }

    fn map_recovery_failure(
        &self,
        recovery: ReplayRecoveryDisposition,
        scope_key: &ReplayScopeKey,
    ) -> AppCoreError {
        let (state, error) = match recovery {
            ReplayRecoveryDisposition::Reconnectable => (
                RuntimeAvailability::Reconnecting,
                AppCoreError::RuntimeUnavailable,
            ),
            ReplayRecoveryDisposition::Incompatible => (
                RuntimeAvailability::Incompatible,
                AppCoreError::RuntimeIncompatible,
            ),
            ReplayRecoveryDisposition::ResyncRequired => (
                RuntimeAvailability::ResyncRequired,
                AppCoreError::ReplayResyncRequired,
            ),
            ReplayRecoveryDisposition::Revoked => {
                (RuntimeAvailability::Revoked, AppCoreError::RuntimeRevoked)
            }
            ReplayRecoveryDisposition::Fatal => (
                RuntimeAvailability::Fatal,
                AppCoreError::RuntimeIdentityConflict,
            ),
        };
        if state == RuntimeAvailability::ResyncRequired {
            let _ = self.set_resync_required_for_scope(scope_key.clone());
        } else {
            let _ = self.set_runtime_failure(state);
        }
        error
    }
}
