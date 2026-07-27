//! Fail-closed `POST /session` compatibility orchestration.

use std::sync::Arc;

use gocode_api::{
    ApiCommandContext, CreateConversationInput, CreateConversationOutput, NonNegativeUnixMillis,
    OpenCodeSessionInfo, SessionHostPort,
};
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use jsonschema::JSONSchema;
use sha2::{Digest, Sha256};

use crate::binding::{
    BindingRuntimeAuthorityId, EnsurePendingResult, MAX_RECOVERY_PENDING_LIMIT,
    SessionBindingContext, SessionBindingKey, SessionBindingStatus, SessionBindingStore,
    SessionCreateFingerprint,
};
use crate::error::{RecoveryListError, SessionCreateError};
use crate::profile::{
    OPENCODE_BASELINE_INVENTORY_PROFILE_ID, ProfileRef, SESSION_CREATE_PROFILE_REVISION,
};

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
                gocode_api::ValidationError {
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

/// Computes the deterministic, domain-separated SHA-256 request fingerprint.
pub fn fingerprint(input: &OpenCodeCreateInput) -> SessionCreateFingerprint {
    let mut hasher = Sha256::new();
    write_field(
        &mut hasher,
        b"gocode-opencode-compat/session-create-fingerprint/v1",
    );
    write_optional_string(&mut hasher, input.title.as_deref());
    write_optional_string(&mut hasher, input.workspace_id.as_deref());
    SessionCreateFingerprint::from_bytes(hasher.finalize().into())
}

fn write_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn write_optional_string(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            write_field(hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn validate_supported_fields(input: &OpenCodeCreateInput) -> Result<(), SessionCreateError> {
    for (field, present) in [
        ("parentID", input.parent_id.is_some()),
        ("agent", input.agent.is_some()),
        ("model", input.model.is_some()),
        ("metadata", input.metadata.is_some()),
        ("permission", input.permission.is_some()),
    ] {
        if present {
            return Err(SessionCreateError::UnsupportedField { field });
        }
    }
    Ok(())
}

fn build_session_info(
    key: &SessionBindingKey,
    context: &SessionBindingContext,
    output: &CreateConversationOutput,
    schema: &JSONSchema,
) -> Result<OpenCodeSessionInfo, SessionCreateError> {
    let mut value = serde_json::json!({
        "id": key.session_id.as_str(),
        "slug": key.session_id.as_str(),
        "projectID": context.response_seed.project_id,
        "directory": context.response_seed.directory,
        "title": context.title.as_deref().unwrap_or("Untitled"),
        "version": context.response_seed.version,
        "time": {
            "created": output.committed_at.as_i64(),
            "updated": output.committed_at.as_i64(),
        },
    });
    if let Some(path) = &context.response_seed.path {
        value["path"] = serde_json::Value::String(path.clone());
    }
    if let Some(workspace_id) = &context.response_seed.workspace_id {
        value["workspaceID"] = serde_json::Value::String(workspace_id.clone());
    }
    OpenCodeSessionInfo::from_json(value, schema).map_err(SessionCreateError::Validation)
}
