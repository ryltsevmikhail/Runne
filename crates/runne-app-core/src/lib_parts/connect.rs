impl AppCore {
    /// Loads the protected local profile and performs the authenticated exact
    /// profile handshake.
    ///
    /// # Errors
    ///
    /// Returns a redacted runtime failure and leaves a closed connection
    /// disposition for diagnostics/UI.
    pub async fn connect_runtime(&self) -> Result<RuntimeAvailability, AppCoreError> {
        let _connect = self.runtime_connect.lock().await;
        let _operation = self.runtime_operation.lock().await;
        self.replace_runtime_client(None)?;
        if self.runtime_mode == RuntimeMode::Bundled {
            self.invalidate_bundled_activation_lease()?;
            self.set_runtime_failure(RuntimeAvailability::Reconnecting)?;
            self.set_runtime_lifecycle(RuntimeLifecycleStatus::Failed)?;
            self.set_runtime_failure_code(Some(
                RuntimeFailureCode::ProtectedActivationUnavailable,
            ))?;
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let profile_path = self
            .runtime_profile_path
            .as_deref()
            .ok_or(AppCoreError::RuntimeUnavailable)?;
        let profile = match LocalRuntimeProfile::load(profile_path) {
            Ok(profile) => profile,
            Err(error) => {
                self.set_runtime_failure(map_profile_state(error))?;
                return Err(AppCoreError::RuntimeUnavailable);
            }
        };
        let current = self.runtime_availability()?;
        if !matches!(
            current,
            RuntimeAvailability::Unconfigured | RuntimeAvailability::Reconnecting
        ) {
            self.set_runtime_failure(RuntimeAvailability::Reconnecting)?;
        }
        self.transition_runtime(RuntimeAvailability::ProfileLoaded)?;
        let client = match profile.connect(RUNTIME_REQUEST_TIMEOUT).await {
            Ok(client) => client,
            Err(error) => {
                self.set_runtime_failure(map_connect_state(&error))?;
                return Err(AppCoreError::RuntimeUnavailable);
            }
        };
        self.transition_runtime(RuntimeAvailability::PeerVerified)?;
        self.transition_runtime(RuntimeAvailability::BootstrapProved)?;
        self.transition_runtime(RuntimeAvailability::Authenticated)?;
        self.replace_runtime_client(Some(client))?;
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        let mut recovery_fence = RuntimeRecoveryFence::new(self);
        if self
            .recover_anchored_mutations_v7_under_operation()
            .await
            .is_err()
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.transition_runtime(RuntimeAvailability::Live)?;
        recovery_fence.disarm();
        Ok(RuntimeAvailability::Live)
    }
    /// Creates or restores the one durable runtime Conversation bound to a
    /// local project.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed local reference, project, or runtime failure.
    pub async fn open_project_conversation(
        &self,
        project_id: i64,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.live_runtime_operation_context()?;
        self.open_project_conversation_under_operation(project_id, &context)
            .await
    }
    async fn open_project_conversation_under_operation(
        &self,
        project_id: i64,
        context: &RuntimeOperationContext,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        self.open_conversation_owner_under_operation(
            ConversationReferenceOwner::Project(project_id),
            context,
        )
        .await
    }
    async fn open_conversation_owner_under_operation(
        &self,
        owner: ConversationReferenceOwner,
        context: &RuntimeOperationContext,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        if let ConversationReferenceOwner::Workspace(workspace_id) = owner {
            let workspace = context
                .client
                .get_workspace(workspace_id)
                .await
                .map_err(|_| AppCoreError::ProjectUnavailable)?;
            if workspace.id() != workspace_id {
                return Err(AppCoreError::ProjectUnavailable);
            }
        }
        let reference = match owner {
            ConversationReferenceOwner::Project(project_id) => {
                self.load_or_prepare_conversation_reference(project_id)?
            }
            ConversationReferenceOwner::Workspace(workspace_id) => {
                self.load_or_prepare_workspace_conversation_reference(&workspace_id.to_string())?
            }
        };
        if reference
            .bound()
            .is_some_and(|bound| !context.identity.matches_reference(bound))
        {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        if reference.bound().is_none() {
            let identity = CommandIdentity::new(
                reference.create_command_id(),
                reference.idempotency_key().to_owned(),
            )
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
            let created = self
                .dispatch_conversation_create_under_operation(
                    context,
                    reference.conversation_id(),
                    reference.workspace_id(),
                    identity,
                    reference.idempotency_key().to_owned(),
                )
                .await?;
            if created.conversation_id != reference.conversation_id()
                || created.workspace_id != reference.workspace_id()
            {
                return Err(AppCoreError::RuntimeUnavailable);
            }
        }
        self.require_current_operation_context(context)?;
        let reference = self.bind_conversation_reference_for_owner(owner, reference, &context.identity)?;
        self.reconcile_conversation_under_operation(context, &reference, |_| {})
            .await
    }

    /// Sends one user message and returns the complete authoritative timeline.
    ///
    /// # Errors
    ///
    /// Returns a typed local/runtime failure without exposing credentials.
    pub async fn send_project_message(
        &self,
        project_id: i64,
        text: &str,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.live_runtime_operation_context()?;
        let current = self
            .open_project_conversation_under_operation(project_id, &context)
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
        let reference = self.load_or_prepare_conversation_reference(project_id)?;
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

    /// Reconciles an affected retained replay scope through the authenticated
    /// V2 shadow-promotion path.
    ///
    /// # Errors
    ///
    /// Returns a closed replay or runtime failure when resync is not admitted.
    pub async fn resync_project_conversation(
        &self,
        project_id: i64,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.resync_runtime_operation_context()?;
        self.resync_conversation_owner(ConversationReferenceOwner::Project(project_id), &context)
            .await
    }
}
