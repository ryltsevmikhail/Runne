#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedTaskDraft {
    pub revision: u64,
    pub prompt: Option<String>,
    pub scope_token: String,
}

impl AppCore {
    /// Loads the current authenticated draft for a canonical workspace.
    ///
    /// # Errors
    /// Returns an error when workspace authorization, runtime identity, or protected storage is unavailable.
    pub async fn load_managed_task_draft(
        &self,
        project_id: &str,
        workspace_id: &str,
    ) -> Result<ManagedTaskDraft, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let (context, scope) = self.managed_draft_scope(project_id, workspace_id).await?;
        self.with_managed_draft_fence(&context, |store, security| {
            let draft = store
                .load_protected_draft(security.secure.as_ref(), &scope)
                .map_err(|error| map_protected_draft_error(&error))?;
            Ok(ManagedTaskDraft {
                revision: draft.revision,
                prompt: draft.prompt,
                scope_token: draft.scope_token,
            })
        })
    }

    /// Saves a new revision only for the token returned by the same durable scope.
    ///
    /// # Errors
    /// Returns an error when authorization, scope token, expected revision, or protected storage is invalid.
    pub async fn save_managed_task_draft(
        &self,
        project_id: &str,
        workspace_id: &str,
        scope_token: &str,
        expected_revision: u64,
        prompt: &str,
    ) -> Result<ManagedTaskDraft, AppCoreError> {
        if prompt.is_empty() || prompt.len() > 64 * 1024 {
            return Err(AppCoreError::InvalidMutation);
        }
        let _operation = self.runtime_operation.lock().await;
        let (context, scope) = self.managed_draft_scope(project_id, workspace_id).await?;
        self.with_managed_draft_fence(&context, |store, security| {
            let draft = store
                .save_protected_draft(
                    security.secure.as_ref(),
                    &scope,
                    scope_token,
                    expected_revision,
                    prompt,
                )
                .map_err(|error| map_protected_draft_error(&error))?;
            Ok(ManagedTaskDraft {
                revision: draft.revision,
                prompt: draft.prompt,
                scope_token: draft.scope_token,
            })
        })
    }

    /// Clears the submitted revision using a retry-safe authenticated tombstone.
    ///
    /// # Errors
    /// Returns an error when authorization, scope token, expected revision, or protected storage is invalid.
    pub async fn clear_managed_task_draft(
        &self,
        project_id: &str,
        workspace_id: &str,
        scope_token: &str,
        expected_revision: u64,
    ) -> Result<ManagedTaskDraft, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let (context, scope) = self.managed_draft_scope(project_id, workspace_id).await?;
        self.with_managed_draft_fence(&context, |store, security| {
            let draft = store
                .clear_protected_draft(
                    security.secure.as_ref(),
                    &scope,
                    scope_token,
                    expected_revision,
                )
                .map_err(|error| map_protected_draft_error(&error))?;
            Ok(ManagedTaskDraft {
                revision: draft.revision,
                prompt: draft.prompt,
                scope_token: draft.scope_token,
            })
        })
    }

    async fn managed_draft_scope(
        &self,
        project_id: &str,
        workspace_id: &str,
    ) -> Result<
        (
            RuntimeOperationContext,
            runne_local_store::ProtectedDraftScope,
        ),
        AppCoreError,
    > {
        let project = CanonicalId::parse(project_id).map_err(|_| AppCoreError::InvalidMutation)?;
        let workspace_id =
            CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::InvalidMutation)?;
        if self.effective_runtime_availability()? != RuntimeAvailability::Live {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let context = self.live_runtime_operation_context()?;
        let workspace = context
            .client
            .get_workspace(workspace_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        if self.effective_runtime_availability()? != RuntimeAvailability::Live {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.require_current_operation_context(&context)?;
        if workspace.id() != workspace_id || workspace.project_id() != project {
            return Err(AppCoreError::ProjectUnavailable);
        }
        let identity = context.identity.clone();
        Ok((
            context,
            runne_local_store::ProtectedDraftScope {
                lineage: identity.lineage,
                authority: identity.authority,
                principal: identity.principal,
                project_id: project.to_string(),
                workspace_id: workspace.id().to_string(),
            },
        ))
    }

    fn with_managed_draft_fence<T>(
        &self,
        expected: &RuntimeOperationContext,
        operation: impl FnOnce(&LocalStore, &MutationSecurityContext) -> Result<T, AppCoreError>,
    ) -> Result<T, AppCoreError> {
        // Lock order: pending resync -> runtime state -> runtime client -> local store.
        let pending = self
            .pending_resync_scopes
            .read()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let availability = self
            .runtime_state
            .read()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let client = self
            .runtime_client
            .read()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        if !pending.is_empty()
            || *availability != RuntimeAvailability::Live
            || self.mutation_gate_epoch.load(Ordering::Acquire) != expected.gate_epoch
            || client.as_ref().is_none_or(|current| {
                replay::StableRuntimeIdentity::from_client(current) != expected.identity
            })
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let security = self
            .mutation_security
            .as_ref()
            .ok_or(AppCoreError::MutationUnavailable)?;
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let result = operation(&store, security)?;
        drop(store);
        if self.mutation_gate_epoch.load(Ordering::Acquire) != expected.gate_epoch {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        drop(client);
        drop(availability);
        drop(pending);
        Ok(result)
    }
}

const fn map_protected_draft_error(error: &runne_local_store::ProtectedDraftError) -> AppCoreError {
    match error {
        runne_local_store::ProtectedDraftError::Conflict => AppCoreError::ManagedDraftConflict,
        runne_local_store::ProtectedDraftError::ScopeMismatch => {
            AppCoreError::ManagedDraftScopeChanged
        }
        runne_local_store::ProtectedDraftError::Capacity => AppCoreError::ManagedDraftCapacity,
        runne_local_store::ProtectedDraftError::Invalid => AppCoreError::InvalidMutation,
        runne_local_store::ProtectedDraftError::Unavailable
        | runne_local_store::ProtectedDraftError::Storage => AppCoreError::MutationUnavailable,
    }
}
