#[derive(Clone, Copy)]
enum ConversationReferenceOwner {
    Project(i64),
    Workspace(CanonicalId),
    TextOnly,
}

impl ConversationReferenceOwner {
    fn key(self) -> String {
        match self {
            Self::Project(project_id) => format!("runtime.conversation.project.{project_id}"),
            Self::Workspace(workspace_id) => {
                format!("runtime.conversation.workspace.{workspace_id}")
            }
            Self::TextOnly => "runtime.conversation.text-only.v1".to_owned(),
        }
    }

    fn workspace_id(self) -> CanonicalId {
        match self {
            Self::Project(_) | Self::TextOnly => CanonicalId::now_v7(),
            Self::Workspace(workspace_id) => workspace_id,
        }
    }

    const fn text_only(self) -> bool {
        matches!(self, Self::TextOnly)
    }
}

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
        let reference = Self::load_or_prepare_conversation_reference_in_store(
            &mut store,
            ConversationReferenceOwner::Project(project_id),
        );
        drop(store);
        reference
    }

    fn load_or_prepare_workspace_conversation_reference(
        &self,
        workspace_id: &str,
    ) -> Result<StoredConversationReference, AppCoreError> {
        let workspace_id =
            CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let reference = Self::load_or_prepare_conversation_reference_in_store(
            &mut store,
            ConversationReferenceOwner::Workspace(workspace_id),
        );
        drop(store);
        reference
    }

    fn load_or_prepare_conversation_reference_in_store(
        store: &mut LocalStore,
        owner: ConversationReferenceOwner,
    ) -> Result<StoredConversationReference, AppCoreError> {
        let key = owner.key();
        if let Some(serialized) = store.get_setting(&key)? {
            let reference = parse_conversation_reference(&serialized)?;
            if reference.text_only() != owner.text_only() {
                return Err(AppCoreError::InvalidConversationReference);
            }
            return Ok(reference);
        }
        let command_id = CanonicalId::now_v7();
        let reference = StoredConversationReference::V1(StoredConversationReferenceV1 {
            schema_version: 1,
            conversation_id: CanonicalId::now_v7(),
            workspace_id: owner.workspace_id(),
            create_command_id: command_id,
            idempotency_key: command_id.to_string(),
            text_only: owner.text_only(),
        });
        let serialized = serde_json::to_string(&reference)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        store.set_setting(&key, &serialized)?;
        Ok(reference)
    }

    #[cfg(test)]
    fn bind_conversation_reference(
        &self,
        project_id: i64,
        reference: StoredConversationReference,
        identity: &replay::StableRuntimeIdentity,
    ) -> Result<StoredConversationReference, AppCoreError> {
        self.bind_conversation_reference_for_owner(
            ConversationReferenceOwner::Project(project_id),
            reference,
            identity,
        )
    }

    #[allow(clippy::too_many_lines)]
    async fn reconcile_conversation_under_operation<F>(
        &self,
        context: &RuntimeOperationContext,
        reference: &StoredConversationReference,
        mut on_update: F,
    ) -> Result<ConversationSnapshot, AppCoreError>
    where
        F: FnMut(ConversationTimelineUpdate),
    {
        self.require_current_operation_context(context)?;
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        let scope_key = context.identity.scope(reference);
        let checkpoint_result = {
            let mut store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            replay::checkpoint(
                &mut store,
                self.mutation_security
                    .as_ref()
                    .map(|value| value.secure.as_ref()),
                &scope_key,
            )
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
        let result = context
            .client
            .catch_up_from_persisted_cursor(
                scope,
                checkpoint.as_ref().map(|value| value.cursor.as_str()),
                ReplayIdentityTracker::new(),
                |delivery| {
                    let Ok(mut store) = self.store.lock() else {
                        local_error = Some(AppCoreError::StateUnavailable);
                        return Err(());
                    };
                    match replay::apply_delivery(
                        &mut store,
                        self.mutation_security
                            .as_ref()
                            .map(|value| value.secure.as_ref()),
                        reference,
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
        if let Err(error) = result {
            if let Some(error) = local_error {
                self.set_runtime_failure(RuntimeAvailability::Fatal)?;
                return Err(error);
            }
            if let Some(baseline) = error.retention_baseline_v2() {
                self.promote_retention_baseline_v2_under_operation(
                    context,
                    scope,
                    &scope_key,
                    checkpoint.as_ref(),
                    baseline,
                )
                .await?;
            } else {
                return Err(self.map_replay_failure(&error, &scope_key));
            }
        }
        self.require_current_operation_context(context)?;
        let snapshot_result = {
            let mut store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            replay::snapshot(
                &mut store,
                self.mutation_security
                    .as_ref()
                    .map(|value| value.secure.as_ref()),
                &scope_key,
                reference,
            )
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
