impl AppCore {
    /// Opens the dedicated durable TextOnly conversation, isolated from workspaces.
    pub async fn open_text_only_conversation(&self) -> Result<ConversationSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.live_runtime_operation_context()?;
        self.open_conversation_owner_under_operation(ConversationReferenceOwner::TextOnly, &context)
            .await
    }

    /// Sends text only through the dedicated TextOnly conversation.
    pub async fn send_text_only_message(
        &self,
        text: &str,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.live_runtime_operation_context()?;
        let current = self
            .open_conversation_owner_under_operation(ConversationReferenceOwner::TextOnly, &context)
            .await?;
        let conversation_id = CanonicalId::parse(&current.conversation_id)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        let generated = self
            .dispatch_text_generation_under_operation(
                &context,
                conversation_id,
                current.stream_version,
                text,
            )
            .await?;
        if generated.conversation_id != conversation_id {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let reference = self.load_text_only_conversation_reference()?;
        if reference.bound().is_none_or(|bound| !context.identity.matches_reference(bound)) {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        self.require_current_operation_context(&context)?;
        self.reconcile_conversation_under_operation(&context, &reference, |_| {}).await
    }

    /// Creates or restores the durable Conversation bound to one canonical Workspace.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed workspace, local reference, or runtime failure.
    pub async fn open_workspace_conversation(
        &self,
        workspace_id: &str,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.live_runtime_operation_context()?;
        let workspace_id = CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        self.open_conversation_owner_under_operation(
            ConversationReferenceOwner::Workspace(workspace_id),
            &context,
        )
        .await
    }

    /// Sends one message to the Conversation bound to a canonical Workspace.
    ///
    /// # Errors
    ///
    /// Returns a typed local/runtime failure without exposing credentials.
    pub async fn send_workspace_message(
        &self,
        workspace_id: &str,
        text: &str,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.live_runtime_operation_context()?;
        let workspace_id = CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        let current = self
            .open_conversation_owner_under_operation(
                ConversationReferenceOwner::Workspace(workspace_id),
                &context,
            )
            .await?;
        let conversation_id = CanonicalId::parse(&current.conversation_id)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        let generated = self
            .dispatch_text_generation_under_operation(
                &context,
                conversation_id,
                current.stream_version,
                text,
            )
            .await?;
        if generated.conversation_id != conversation_id {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let reference = self.load_or_prepare_workspace_conversation_reference(&workspace_id.to_string())?;
        if reference
            .bound()
            .is_none_or(|bound| !context.identity.matches_reference(bound))
        {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        self.require_current_operation_context(&context)?;
        self.reconcile_conversation_under_operation(&context, &reference, |_| {})
            .await
    }

    /// Reconciles the Conversation bound to one canonical Workspace.
    ///
    /// # Errors
    ///
    /// Returns a closed replay or runtime failure when resync is not admitted.
    pub async fn resync_workspace_conversation(
        &self,
        workspace_id: &str,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.resync_runtime_operation_context()?;
        let workspace_id = CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        self.resync_conversation_owner(ConversationReferenceOwner::Workspace(workspace_id), &context)
            .await
    }

    /// Resynchronizes the dedicated TextOnly conversation after explicit recovery.
    pub async fn resync_text_only_conversation(&self) -> Result<ConversationSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.resync_runtime_operation_context()?;
        self.resync_conversation_owner(ConversationReferenceOwner::TextOnly, &context)
            .await
    }

    async fn resync_conversation_owner(
        &self,
        owner: ConversationReferenceOwner,
        context: &RuntimeOperationContext,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let reference = match owner {
            ConversationReferenceOwner::Project(project_id) => {
                self.load_or_prepare_conversation_reference(project_id)?
            }
            ConversationReferenceOwner::Workspace(workspace_id) => {
                self.load_workspace_conversation_reference(&workspace_id.to_string())?
            }
            ConversationReferenceOwner::TextOnly => self.load_text_only_conversation_reference()?,
        };
        if reference.text_only() != owner.text_only() {
            return Err(AppCoreError::InvalidConversationReference);
        }
        let Some(bound) = reference.bound() else {
            return Err(AppCoreError::InvalidConversationReference);
        };
        if !context.identity.matches_reference(bound) {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        let scope_key = context.identity.scope(&reference);
        if matches!(
            self.runtime_availability()?,
            RuntimeAvailability::Fatal
                | RuntimeAvailability::Incompatible
                | RuntimeAvailability::Revoked
        ) || !self.resync_required_for_scope(&scope_key)?
        {
            return Err(AppCoreError::ReplayResyncRequired);
        }
        match self
            .reconcile_conversation_under_operation(context, &reference, |_| {})
            .await
        {
            Ok(snapshot) => {
                self.clear_resync_scope(&scope_key)?;
                Ok(snapshot)
            }
            Err(error) => {
                if self.runtime_availability()? == RuntimeAvailability::Reconnecting {
                    self.set_resync_required_for_scope(scope_key)?;
                }
                Err(error)
            }
        }
    }
}
