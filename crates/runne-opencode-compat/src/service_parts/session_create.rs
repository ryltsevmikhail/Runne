/// Baseline `Session.create` wire payload.
///
/// `title` and `workspaceID` are currently supported. The other optional
/// baseline fields are retained so this boundary can reject their presence
/// before it writes a binding or calls the runtime host.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenCodeCreateInput {
    /// Supported baseline title.
    pub title: Option<String>,
    /// Supported baseline workspace identifier.
    pub workspace_id: Option<String>,
    /// Unsupported baseline `parentID`.
    pub parent_id: Option<serde_json::Value>,
    /// Unsupported baseline `agent`.
    pub agent: Option<serde_json::Value>,
    /// Unsupported baseline `model`.
    pub model: Option<serde_json::Value>,
    /// Unsupported baseline `metadata`.
    pub metadata: Option<serde_json::Value>,
    /// Unsupported baseline `permission`.
    pub permission: Option<serde_json::Value>,
}

/// Caller-supplied canonical context for one idempotent session create command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCreateRequestContext {
    /// Runtime conversation identity. This is never inferred from `ses_*`.
    pub conversation_id: ConversationId,
    /// Runtime workspace identity.
    pub workspace_id: WorkspaceId,
    /// Runtime command identity.
    pub command_id: CommandId,
    /// Caller-supplied idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Authenticated API context and stable response seed.
    pub api_context: ApiCommandContext,
}

/// Service that translates a constrained baseline request into an idempotent
/// runtime conversation create operation.
pub struct OpenCodeSessionCreateService<B: SessionBindingStore, H: SessionHostPort> {
    binding: B,
    host: H,
    profile: ProfileRef,
    schema: Arc<JSONSchema>,
}

impl<B: SessionBindingStore, H: SessionHostPort> OpenCodeSessionCreateService<B, H> {
    /// Creates a service with a caller-compiled authoritative wire schema.
    pub fn new(binding: B, host: H, profile: ProfileRef, schema: Arc<JSONSchema>) -> Self {
        Self {
            binding,
            host,
            profile,
            schema,
        }
    }

    /// Creates or resumes a baseline session binding without creating TaskRun state.
    pub async fn create_session(
        &self,
        key: SessionBindingKey,
        request: &SessionCreateRequestContext,
        input: OpenCodeCreateInput,
    ) -> Result<OpenCodeSessionInfo, SessionCreateError> {
        self.validate_profile(&key)?;
        validate_supported_fields(&input)?;

        let mut response_seed = request.api_context.response_seed.clone();
        response_seed.workspace_id = input.workspace_id.clone().or(response_seed.workspace_id);
        let context = SessionBindingContext {
            conversation_id: request.conversation_id,
            workspace_id: request.workspace_id,
            command_id: request.command_id,
            idempotency_key: request.idempotency_key.clone(),
            request_fingerprint: fingerprint(&input),
            title: input.title.clone(),
            principal: request.api_context.principal.clone(),
            actor: request.api_context.actor.clone(),
            response_seed,
        };
        self.preflight_response(&key, &context)?;

        let host_context = match self
            .binding
            .ensure_pending(&key, &context)
            .map_err(SessionCreateError::Binding)?
        {
            EnsurePendingResult::Created => context,
            EnsurePendingResult::AlreadyPending => {
                match self
                    .binding
                    .lookup(&key)
                    .map_err(SessionCreateError::Binding)?
                {
                    Some(SessionBindingStatus::Pending { context: stored }) => {
                        if stored != context {
                            return Err(SessionCreateError::ContextConflict { key });
                        }
                        stored
                    }
                    Some(SessionBindingStatus::Committed {
                        context: stored,
                        response,
                    }) => {
                        if stored != context {
                            return Err(SessionCreateError::ContextConflict { key });
                        }
                        return Ok(response);
                    }
                    None => {
                        return Err(SessionCreateError::Binding(
                            crate::binding::BindingError::NotFound(key),
                        ));
                    }
                }
            }
            EnsurePendingResult::AlreadyCommitted => match self
                .binding
                .lookup(&key)
                .map_err(SessionCreateError::Binding)?
            {
                Some(SessionBindingStatus::Committed {
                    context: stored,
                    response,
                }) => {
                    if stored != context {
                        return Err(SessionCreateError::ContextConflict { key });
                    }
                    return Ok(response);
                }
                _ => return Err(SessionCreateError::ImpossibleCommittedBinding { key }),
            },
        };

        self.complete_pending(key, host_context).await
    }

    /// Recreates a pending session from durable binding context only.
    pub async fn recover_pending(
        &self,
        key: SessionBindingKey,
    ) -> Result<OpenCodeSessionInfo, SessionCreateError> {
        self.validate_profile(&key)?;
        match self
            .binding
            .lookup(&key)
            .map_err(SessionCreateError::Binding)?
        {
            Some(SessionBindingStatus::Pending { context }) => {
                self.preflight_response(&key, &context)?;
                self.complete_pending(key, context).await
            }
            Some(SessionBindingStatus::Committed { response, .. }) => Ok(response),
            None => Err(SessionCreateError::Binding(
                crate::binding::BindingError::NotFound(key),
            )),
        }
    }

    /// Lists pending bindings for an explicitly selected runtime authority.
    pub fn list_pending_for_recovery(
        &self,
        authority: &BindingRuntimeAuthorityId,
        limit: usize,
        after: Option<&(NonNegativeUnixMillis, SessionBindingKey)>,
    ) -> Result<Vec<(NonNegativeUnixMillis, SessionBindingKey)>, RecoveryListError> {
        if limit == 0 || limit > MAX_RECOVERY_PENDING_LIMIT {
            return Err(RecoveryListError::InvalidLimit {
                max: MAX_RECOVERY_PENDING_LIMIT,
                actual: limit,
            });
        }
        self.binding
            .list_pending(authority, limit, after)
            .map_err(RecoveryListError::Binding)
    }

    fn validate_profile(&self, key: &SessionBindingKey) -> Result<(), SessionCreateError> {
        if self.profile.profile_id.as_str() != OPENCODE_BASELINE_INVENTORY_PROFILE_ID
            || self.profile.profile_revision != SESSION_CREATE_PROFILE_REVISION
        {
            return Err(SessionCreateError::UnsupportedProfile {
                configured: self.profile.clone(),
            });
        }
        if key.profile_id.as_str() != OPENCODE_BASELINE_INVENTORY_PROFILE_ID
            || key.profile_revision != SESSION_CREATE_PROFILE_REVISION
            || key.profile_id != self.profile.profile_id
            || key.profile_revision != self.profile.profile_revision
        {
            return Err(SessionCreateError::ProfileMismatch {
                configured: self.profile.clone(),
                requested: key.clone(),
            });
        }
        Ok(())
    }

    fn preflight_response(
        &self,
        key: &SessionBindingKey,
        context: &SessionBindingContext,
    ) -> Result<(), SessionCreateError> {
        let Some(committed_at) = NonNegativeUnixMillis::new(i64::MAX) else {
            return Err(SessionCreateError::Validation(
                runne_api::ValidationError {
                    message: "maximum non-negative Unix millisecond is unavailable".into(),
                },
            ));
        };
        let output = CreateConversationOutput {
            conversation_id: context.conversation_id,
            workspace_id: context.workspace_id,
            committed_at,
            stream_version: 1,
        };
        build_session_info(key, context, &output, &self.schema).map(|_| ())
    }

    async fn complete_pending(
        &self,
        key: SessionBindingKey,
        context: SessionBindingContext,
    ) -> Result<OpenCodeSessionInfo, SessionCreateError> {
        let api_context = ApiCommandContext {
            principal: context.principal.clone(),
            actor: context.actor.clone(),
            response_seed: context.response_seed.clone(),
        };
        let host_input = CreateConversationInput {
            conversation_id: context.conversation_id,
            workspace_id: context.workspace_id,
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            scope: runne_api::ConversationContextScope::Workspace,
        };
        let host_output = self
            .host
            .create_conversation(&api_context, host_input)
            .await
            .map_err(SessionCreateError::Host)?;
        if host_output.conversation_id != context.conversation_id
            || host_output.workspace_id != context.workspace_id
            || host_output.stream_version != 1
        {
            return Err(SessionCreateError::HostOutputMismatch { key });
        }
        let info = build_session_info(&key, &context, &host_output, &self.schema)?;
        self.binding
            .commit(&key, context.conversation_id, &info)
            .map_err(SessionCreateError::Binding)?;
        Ok(info)
    }
}
