const MANAGED_TASK_RUN_LIMIT: usize = 256;
const MANAGED_ATTENTION_LIMIT: usize = 64;

impl AppCore {
    /// Resolves the project/workspace scope and only opens its governed
    /// Conversation when authenticated submit authority is available.
    ///
    /// # Errors
    /// Returns a typed `AppCore` error when canonical scope, runtime authority,
    /// or the governed workspace Conversation cannot be resolved.
    pub async fn prepare_managed_task_run(
        &self,
        project_id: &str,
        workspace_id: &str,
    ) -> Result<ManagedTaskRunPreflight, AppCoreError> {
        let _intent_operation = self.managed_intent_operation.lock().await;
        let project =
            CanonicalId::parse(project_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        let workspace = self.get_canonical_workspace(workspace_id).await?;
        if workspace.project_id != project.to_string() {
            return Err(AppCoreError::ProjectUnavailable);
        }
        let (generation, start_identity, reason) = self.live_runtime_client().map_or(
            (None, None, Some("runtime_unavailable")),
            |client| {
                let generation = client.session_info().launch_generation;
                let identity = replay::StableRuntimeIdentity::from_client(&client);
                let capable = client
                    .session_info()
                    .capabilities
                    .iter()
                    .any(|value| value == "task_run.submit.v2");
                let mutability = self
                    .effective_runtime_availability()
                    .is_ok_and(RuntimeAvailability::allows_mutations);
                (
                    Some(generation),
                    Some(identity),
                    if !mutability {
                        Some("mutation_authority_unavailable")
                    } else if !capable {
                        Some("submit_capability_missing")
                    } else {
                        None
                    },
                )
            },
        );
        let mut conversation_id = None;
        let mut recovery_token = None;
        let mut reason = reason;
        if reason.is_none() {
            match self.open_workspace_conversation(workspace_id).await {
                Ok(conversation) => {
                    let current = self.live_runtime_client()?;
                    if Some(replay::StableRuntimeIdentity::from_client(&current)) != start_identity
                    {
                        reason = Some("stale_generation");
                    }
                    if reason.is_none() {
                        conversation_id = Some(conversation.conversation_id);
                        let intent = ManagedTaskRunIntent {
                            runtime: start_identity
                                .clone()
                                .ok_or(AppCoreError::RuntimeUnavailable)?,
                            project_id: project.to_string(),
                            workspace_id: workspace.workspace_id.clone(),
                            conversation_id: conversation_id
                                .clone()
                                .ok_or(AppCoreError::RuntimeUnavailable)?,
                            generation: generation.ok_or(AppCoreError::RuntimeUnavailable)?,
                            recovery_token: CanonicalId::now_v7().to_string(),
                        };
                        let token = self.ensure_managed_intent(intent)?;
                        recovery_token = Some(token);
                    }
                }
                Err(_) => reason = Some("conversation_unavailable"),
            }
        }
        let can_start = reason.is_none();
        #[cfg(target_os = "linux")]
        let draft_policy = if self
            .load_managed_task_draft(&project.to_string(), &workspace.workspace_id)
            .await
            .is_ok()
        {
            ManagedTaskDraftPolicy::ProtectedRestart
        } else {
            ManagedTaskDraftPolicy::Unavailable
        };
        #[cfg(not(target_os = "linux"))]
        let draft_policy = ManagedTaskDraftPolicy::MemoryOnly;
        Ok(ManagedTaskRunPreflight {
            status: if can_start { "ready" } else { "unavailable" },
            generation,
            project_id: project.to_string(),
            workspace_id: workspace.workspace_id,
            conversation_id,
            can_start,
            start_unavailable_reason: reason,
            recovery_token,
            authority: ManagedTaskRunAuthority {
                provider: unavailable_managed_field(),
                model: unavailable_managed_field(),
                policy: unavailable_managed_field(),
            },
            draft_policy,
        })
    }

    /// Starts one managed `TaskRun` with the preflight's exact runtime
    /// generation and opaque durable command identity.
    ///
    /// # Errors
    /// Returns an error when the token, text, scope, runtime generation, or
    /// mutation authority is invalid or unavailable.
    pub async fn start_managed_task_run(
        &self,
        workspace_id: &str,
        conversation_id: &str,
        prompt: String,
        generation: u64,
        recovery_token: &str,
    ) -> Result<ManagedTaskRunStart, AppCoreError> {
        let _intent_operation = self.managed_intent_operation.lock().await;
        if prompt.trim().is_empty() || prompt.len() > runne_api::MAX_TASK_RUN_PROMPT_BYTES {
            return Err(AppCoreError::InvalidMutation);
        }
        let workspace_id =
            CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::InvalidMutation)?;
        let conversation_id =
            CanonicalId::parse(conversation_id).map_err(|_| AppCoreError::InvalidMutation)?;
        let command_id =
            CanonicalId::parse(recovery_token).map_err(|_| AppCoreError::InvalidMutation)?;
        if command_id.to_string() != recovery_token {
            return Err(AppCoreError::InvalidMutation);
        }
        let client = self.live_runtime_client()?;
        if !self.effective_runtime_availability()?.allows_mutations() {
            return Err(AppCoreError::MutationUnavailable);
        }
        let start_identity = replay::StableRuntimeIdentity::from_client(&client);
        if client.session_info().launch_generation != generation {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        if !client
            .session_info()
            .capabilities
            .iter()
            .any(|value| value == "task_run.submit.v2")
        {
            return Err(AppCoreError::MutationUnavailable);
        }
        self.validate_managed_intent(
            &start_identity,
            &workspace_id.to_string(),
            &conversation_id.to_string(),
            generation,
            recovery_token,
        )?;
        let opened = self
            .open_workspace_conversation(&workspace_id.to_string())
            .await?;
        if opened.conversation_id != conversation_id.to_string() {
            return Err(AppCoreError::InvalidConversationReference);
        }
        let current = self.live_runtime_client()?;
        if replay::StableRuntimeIdentity::from_client(&current) != start_identity {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let request = MutationRequest::submit_task_run_with_identity(
            command_id,
            conversation_id,
            workspace_id,
            prompt,
        )?;
        let lease = self.prepare_taskrun_submit_intent(request).await?;
        if lease.runtime_identity != start_identity {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        validate_managed_lease_identity(&lease, recovery_token)?;
        if let Some(result) = managed_lease_accepted_result(&lease, recovery_token)? {
            self.mark_managed_token_accepted(
                recovery_token,
                &start_identity,
                &workspace_id.to_string(),
                &conversation_id.to_string(),
                generation,
            )?;
            return Ok(result);
        }
        match self.dispatch_prepared_mutation(lease).await {
            Ok(MutationDispatchResult::TaskRunSubmitted(value)) => {
                self.mark_managed_token_accepted(
                    recovery_token,
                    &start_identity,
                    &workspace_id.to_string(),
                    &conversation_id.to_string(),
                    generation,
                )?;
                Ok(ManagedTaskRunStart {
                    status: "accepted",
                    task_run_id: Some(value.task_run_id().to_string()),
                    stream_version: Some(value.stream_version()),
                    recovery_token: recovery_token.to_owned(),
                })
            }
            Err(_) => Ok(ManagedTaskRunStart {
                status: "uncertain",
                task_run_id: None,
                stream_version: None,
                recovery_token: recovery_token.to_owned(),
            }),
            Ok(_) => Err(AppCoreError::InvalidMutation),
        }
    }
}
