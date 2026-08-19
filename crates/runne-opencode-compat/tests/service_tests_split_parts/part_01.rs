use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use runne_api::{
    ApiActor, ApiCommandContext, ApiPrincipalId, CreateConversationInput, CreateConversationOutput,
    HostError, NonNegativeUnixMillis, ResponseSeed, SessionHostPort,
};
use runne_domain::id::{ConversationId, IdempotencyKey};
use runne_opencode_compat::profile::{ProfileId, ProfileRef};
use runne_opencode_compat::{
    BindingError, BindingRuntimeAuthorityId, EnsurePendingResult, OpenCodeCreateInput,
    OpenCodeSessionCreateService, OpenCodeSessionId, RecoveryListError, SessionBindingContext,
    SessionBindingKey, SessionBindingStatus, SessionBindingStore, SessionCreateError,
    SessionCreateRequestContext, fingerprint,
};
use jsonschema::{Draft, JSONSchema};
use serde::Deserialize;

const UUID_A: &str = "018f2e3a-7000-7000-8000-000000000001";
const UUID_B: &str = "018f2e3a-7000-7000-8000-000000000002";
const UUID_C: &str = "018f2e3a-7000-7000-8000-000000000003";

#[derive(Clone, Default)]
struct MockBindingStore {
    bindings: Arc<Mutex<HashMap<SessionBindingKey, SessionBindingStatus>>>,
    ensure_calls: Arc<Mutex<usize>>,
    list_calls: Arc<Mutex<Vec<(BindingRuntimeAuthorityId, usize)>>>,
    commit_failure: Arc<Mutex<Option<BindingError>>>,
}

impl MockBindingStore {
    fn status(&self, key: &SessionBindingKey) -> Option<SessionBindingStatus> {
        self.bindings.lock().unwrap().get(key).cloned()
    }

    fn ensure_calls(&self) -> usize {
        *self.ensure_calls.lock().unwrap()
    }

    fn set_commit_failure(&self, error: BindingError) {
        *self.commit_failure.lock().unwrap() = Some(error);
    }

    fn clear_commit_failure(&self) {
        *self.commit_failure.lock().unwrap() = None;
    }
}

impl SessionBindingStore for MockBindingStore {
    fn ensure_pending(
        &self,
        key: &SessionBindingKey,
        context: &SessionBindingContext,
    ) -> Result<EnsurePendingResult, BindingError> {
        *self.ensure_calls.lock().unwrap() += 1;
        let mut bindings = self.bindings.lock().unwrap();
        match bindings.get(key) {
            Some(SessionBindingStatus::Pending { .. }) => Ok(EnsurePendingResult::AlreadyPending),
            Some(SessionBindingStatus::Committed { .. }) => {
                Ok(EnsurePendingResult::AlreadyCommitted)
            }
            None => {
                bindings.insert(
                    key.clone(),
                    SessionBindingStatus::Pending {
                        context: context.clone(),
                    },
                );
                Ok(EnsurePendingResult::Created)
            }
        }
    }

    fn commit(
        &self,
        key: &SessionBindingKey,
        expected_conversation_id: ConversationId,
        response: &runne_api::OpenCodeSessionInfo,
    ) -> Result<(), BindingError> {
        if let Some(error) = &*self.commit_failure.lock().unwrap() {
            return Err(error.clone());
        }
        let mut bindings = self.bindings.lock().unwrap();
        match bindings.get(key).cloned() {
            Some(SessionBindingStatus::Pending { context })
                if context.conversation_id == expected_conversation_id =>
            {
                bindings.insert(
                    key.clone(),
                    SessionBindingStatus::Committed {
                        context,
                        response: response.clone(),
                    },
                );
                Ok(())
            }
            Some(SessionBindingStatus::Committed { response: old, .. }) if old == *response => {
                Ok(())
            }
            Some(_) => Err(BindingError::Conflict(key.clone())),
            None => Err(BindingError::NotFound(key.clone())),
        }
    }

    fn lookup(
        &self,
        key: &SessionBindingKey,
    ) -> Result<Option<SessionBindingStatus>, BindingError> {
        Ok(self.status(key))
    }

    fn list_pending(
        &self,
        authority: &BindingRuntimeAuthorityId,
        limit: usize,
        _after: Option<&(NonNegativeUnixMillis, SessionBindingKey)>,
    ) -> Result<Vec<(NonNegativeUnixMillis, SessionBindingKey)>, BindingError> {
        self.list_calls
            .lock()
            .unwrap()
            .push((authority.clone(), limit));
        Ok(Vec::new())
    }
}

#[derive(Clone)]
struct MockHost {
    calls: Arc<Mutex<usize>>,
    failure: Arc<Mutex<Option<HostError>>>,
}

impl MockHost {
    fn succeeds() -> Self {
        Self {
            calls: Arc::new(Mutex::new(0)),
            failure: Arc::new(Mutex::new(None)),
        }
    }

    fn fails(error: HostError) -> Self {
        Self {
            calls: Arc::new(Mutex::new(0)),
            failure: Arc::new(Mutex::new(Some(error))),
        }
    }

    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl SessionHostPort for MockHost {
    async fn create_conversation(
        &self,
        _ctx: &ApiCommandContext,
        input: CreateConversationInput,
    ) -> Result<CreateConversationOutput, HostError> {
        *self.calls.lock().unwrap() += 1;
        if let Some(error) = &*self.failure.lock().unwrap() {
            return Err(error.clone());
        }
        Ok(CreateConversationOutput {
            conversation_id: input.conversation_id,
            workspace_id: input.workspace_id,
            committed_at: NonNegativeUnixMillis::new(1_000).unwrap(),
            stream_version: 1,
        })
    }
}

fn schema() -> Arc<JSONSchema> {
    let value = serde_json::from_str(include_str!(
        "../../../../docs/schemas/session-info-v1.schema.json"
    ))
    .unwrap();
    Arc::new(
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&value)
            .unwrap(),
    )
}

fn key() -> SessionBindingKey {
    SessionBindingKey {
        session_id: OpenCodeSessionId::new("ses_baseline_1").unwrap(),
        profile_id: ProfileId::new("opencode-baseline-inventory").expect("profile"),
        profile_revision: 2,
        runtime_authority_id: BindingRuntimeAuthorityId::new("runtime-a").unwrap(),
    }
}

fn request() -> SessionCreateRequestContext {
    SessionCreateRequestContext {
        conversation_id: UUID_A.parse().unwrap(),
        workspace_id: UUID_B.parse().unwrap(),
        command_id: UUID_C.parse().unwrap(),
        idempotency_key: IdempotencyKey::new("session-create-1").unwrap(),
        api_context: ApiCommandContext {
            principal: ApiPrincipalId::new("principal-1").unwrap(),
            actor: ApiActor::new("actor-1").unwrap(),
            response_seed: ResponseSeed {
                project_id: "project-1".into(),
                directory: "/workspace".into(),
                path: Some("/workspace/file.rs".into()),
                version: "1.0.0".into(),
                workspace_id: Some("seed-workspace".into()),
            },
        },
    }
}

fn input() -> OpenCodeCreateInput {
    OpenCodeCreateInput {
        title: Some("New session".into()),
        workspace_id: Some("wire-workspace".into()),
        parent_id: None,
        agent: None,
        model: None,
        metadata: None,
        permission: None,
    }
}

fn service(
    binding: MockBindingStore,
    host: MockHost,
) -> OpenCodeSessionCreateService<MockBindingStore, MockHost> {
    OpenCodeSessionCreateService::new(
        binding,
        host,
        ProfileRef {
            profile_id: ProfileId::new("opencode-baseline-inventory").expect("profile"),
            profile_revision: 2,
        },
        schema(),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenCreateRequest {
    title: String,
    #[serde(rename = "workspaceID")]
    workspace_id: String,
}
