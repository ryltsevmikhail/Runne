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
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = None;
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
        *self
            .runtime_client
            .write()
            .map_err(|_| AppCoreError::StateUnavailable)? = Some(client);
        self.transition_runtime(RuntimeAvailability::Reconciling)?;
        self.transition_runtime(RuntimeAvailability::Live)?;
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
        self.open_project_conversation_inner(project_id).await
    }

    async fn open_project_conversation_inner(
        &self,
        project_id: i64,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let client = self.live_runtime_client()?;
        let reference = self.load_or_prepare_conversation_reference(project_id)?;
        let identity = replay::StableRuntimeIdentity::from_client(&client);
        if reference
            .bound()
            .is_some_and(|bound| !identity.matches_reference(bound))
        {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        let identity = CommandIdentity::new(
            reference.create_command_id(),
            reference.idempotency_key().to_owned(),
        )
        .map_err(|_| AppCoreError::InvalidConversationReference)?;
        let created = client
            .create_conversation(CreateConversationRequest::new(
                identity,
                reference.conversation_id(),
                reference.workspace_id(),
            ))
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        if created.conversation_id != reference.conversation_id()
            || created.workspace_id != reference.workspace_id()
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let stable_identity = replay::StableRuntimeIdentity::from_client(&client);
        let reference =
            self.bind_conversation_reference(project_id, reference, &stable_identity)?;
        self.reconcile_conversation(&client, &reference, &stable_identity, |_| {})
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
        let current = self.open_project_conversation_inner(project_id).await?;
        let conversation_id = CanonicalId::parse(&current.conversation_id)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        let client = self.live_runtime_client()?;
        let generated = client
            .generate_text(
                GenerateTextRequest::new(
                    new_command_identity()?,
                    conversation_id,
                    current.stream_version,
                    text,
                )
                .map_err(|_| AppCoreError::RuntimeUnavailable)?,
            )
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        if generated.conversation_id != conversation_id {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let reference = self.load_or_prepare_conversation_reference(project_id)?;
        let identity = replay::StableRuntimeIdentity::from_client(&client);
        if reference
            .bound()
            .is_none_or(|bound| !identity.matches_reference(bound))
        {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        self.reconcile_conversation(&client, &reference, &identity, |_| {})
            .await
    }

    /// Explicitly discards only the affected retained replay projection and
    /// rebuilds it from the runtime's current authoritative floor.
    ///
    /// # Errors
    ///
    /// This operation is admitted only from `resync_required`; identity
    /// mismatch or local reset failure remains fail-closed.
    pub async fn resync_project_conversation(
        &self,
        project_id: i64,
    ) -> Result<ConversationSnapshot, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let client = self
            .runtime_client()?
            .ok_or(AppCoreError::RuntimeUnavailable)?;
        let reference = self.load_or_prepare_conversation_reference(project_id)?;
        let identity = replay::StableRuntimeIdentity::from_client(&client);
        let Some(bound) = reference.bound() else {
            return Err(AppCoreError::InvalidConversationReference);
        };
        if !identity.matches_reference(bound) {
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        let scope_key = identity.scope(&reference);
        if matches!(
            self.runtime_availability()?,
            RuntimeAvailability::Fatal
                | RuntimeAvailability::Incompatible
                | RuntimeAvailability::Revoked
        ) || !self.resync_required_for_scope(&scope_key)?
        {
            return Err(AppCoreError::ReplayResyncRequired);
        }
        {
            let mut store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            store.reset_replay_scope(&scope_key).map_err(|_| {
                let _ = self.set_runtime_failure(RuntimeAvailability::Fatal);
                AppCoreError::LocalProjectionUnavailable
            })?;
        }
        match self
            .reconcile_conversation(&client, &reference, &identity, |_| {})
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
