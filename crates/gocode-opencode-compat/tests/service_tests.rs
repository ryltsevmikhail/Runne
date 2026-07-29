use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gocode_api::{
    ApiActor, ApiCommandContext, ApiPrincipalId, CreateConversationInput, CreateConversationOutput,
    HostError, NonNegativeUnixMillis, ResponseSeed, SessionHostPort,
};
use gocode_domain::id::{ConversationId, IdempotencyKey};
use gocode_opencode_compat::profile::{ProfileId, ProfileRef};
use gocode_opencode_compat::{
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
        response: &gocode_api::OpenCodeSessionInfo,
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
        "../../../docs/schemas/session-info-v1.schema.json"
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

#[tokio::test]
async fn golden_session_create_request_and_response_are_byte_exact() {
    let request_bytes = include_bytes!("../../../docs/golden/session-create-request-v1.json");
    assert_eq!(
        request_bytes,
        b"{\"title\":\"Golden Session\",\"workspaceID\":\"workspace-wire-id\"}\n"
    );
    let wire: GoldenCreateRequest = serde_json::from_slice(request_bytes).unwrap();
    let key = SessionBindingKey {
        session_id: OpenCodeSessionId::new("ses_golden").unwrap(),
        profile_id: ProfileId::new("opencode-baseline-inventory").unwrap(),
        profile_revision: 2,
        runtime_authority_id: BindingRuntimeAuthorityId::new("runtime-golden").unwrap(),
    };
    let request = SessionCreateRequestContext {
        conversation_id: UUID_A.parse().unwrap(),
        workspace_id: UUID_B.parse().unwrap(),
        command_id: UUID_C.parse().unwrap(),
        idempotency_key: IdempotencyKey::new("golden-session-create").unwrap(),
        api_context: ApiCommandContext {
            principal: ApiPrincipalId::new("golden-principal").unwrap(),
            actor: ApiActor::new("golden-actor").unwrap(),
            response_seed: ResponseSeed {
                project_id: "golden-project".into(),
                directory: "/tmp/golden".into(),
                path: Some("/tmp/golden".into()),
                version: "1.0".into(),
                workspace_id: Some(wire.workspace_id.clone()),
            },
        },
    };
    let response = service(MockBindingStore::default(), MockHost::succeeds())
        .create_session(
            key,
            &request,
            OpenCodeCreateInput {
                title: Some(wire.title),
                workspace_id: Some(wire.workspace_id),
                parent_id: None,
                agent: None,
                model: None,
                metadata: None,
                permission: None,
            },
        )
        .await
        .unwrap();

    let actual = serde_json::to_vec(response.as_value()).unwrap();
    let expected = include_bytes!("../../../docs/golden/session-create-response-v1.json");
    assert_eq!(actual, expected.strip_suffix(b"\n").unwrap());
}

#[tokio::test]
async fn success_commits_a_schema_valid_response() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let result = service(binding.clone(), host.clone())
        .create_session(key(), &request(), input())
        .await
        .unwrap();

    assert_eq!(host.calls(), 1);
    assert_eq!(result.as_value()["id"], "ses_baseline_1");
    assert_eq!(result.as_value()["workspaceID"], "wire-workspace");
    assert!(matches!(
        binding.status(&key()),
        Some(SessionBindingStatus::Committed { .. })
    ));
}

#[tokio::test]
async fn committed_retry_returns_stored_response_without_host_call() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let sut = service(binding, host.clone());
    let first = sut
        .create_session(key(), &request(), input())
        .await
        .unwrap();
    let retry = sut
        .create_session(key(), &request(), input())
        .await
        .unwrap();

    assert_eq!(first, retry);
    assert_eq!(host.calls(), 1);
}

#[tokio::test]
async fn host_failure_keeps_binding_pending() {
    let binding = MockBindingStore::default();
    let host = MockHost::fails(HostError::Timeout);
    let error = service(binding.clone(), host.clone())
        .create_session(key(), &request(), input())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SessionCreateError::Host(HostError::Timeout)
    ));
    assert_eq!(host.calls(), 1);
    assert!(matches!(
        binding.status(&key()),
        Some(SessionBindingStatus::Pending { .. })
    ));
}

#[tokio::test]
async fn recovery_rebuilds_response_after_host_success_and_commit_failure() {
    let binding = MockBindingStore::default();
    binding.set_commit_failure(BindingError::StorageFailure);
    let host = MockHost::succeeds();
    let sut = service(binding.clone(), host.clone());
    let create_input = input();
    let error = sut
        .create_session(key(), &request(), create_input)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SessionCreateError::Binding(BindingError::StorageFailure)
    ));

    binding.clear_commit_failure();
    let recovered = sut.recover_pending(key()).await.unwrap();

    assert_eq!(host.calls(), 2);
    assert_eq!(recovered.as_value()["title"], "New session");
    assert_eq!(recovered.as_value()["workspaceID"], "wire-workspace");
    assert!(matches!(
        binding.status(&key()),
        Some(SessionBindingStatus::Committed { .. })
    ));
}

#[tokio::test]
async fn context_or_fingerprint_conflict_never_calls_host() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let sut = service(binding.clone(), host.clone());
    sut.create_session(key(), &request(), input())
        .await
        .unwrap();

    let mut changed = input();
    changed.title = Some("Different title".into());
    let error = sut
        .create_session(key(), &request(), changed)
        .await
        .unwrap_err();
    assert!(matches!(error, SessionCreateError::ContextConflict { .. }));
    assert_eq!(host.calls(), 1);
    assert_eq!(binding.ensure_calls(), 2);
}

#[tokio::test]
async fn unsupported_field_has_no_binding_or_host_side_effect() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let mut rejected = input();
    rejected.permission = Some(serde_json::json!([]));
    let error = service(binding.clone(), host.clone())
        .create_session(key(), &request(), rejected)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SessionCreateError::UnsupportedField {
            field: "permission"
        }
    ));
    assert_eq!(binding.ensure_calls(), 0);
    assert_eq!(host.calls(), 0);
}

#[tokio::test]
async fn oversized_durable_response_is_rejected_before_binding_or_host() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let mut oversized = input();
    oversized.title = Some("x".repeat(gocode_api::OpenCodeSessionInfo::MAX_WIRE_BYTES));
    let error = service(binding.clone(), host.clone())
        .create_session(key(), &request(), oversized)
        .await
        .unwrap_err();

    assert!(matches!(error, SessionCreateError::Validation(_)));
    assert_eq!(binding.ensure_calls(), 0);
    assert_eq!(host.calls(), 0);
}

#[tokio::test]
async fn profile_mismatch_has_no_binding_or_host_side_effect() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let mut wrong_key = key();
    wrong_key.profile_revision = 1;
    let error = service(binding.clone(), host.clone())
        .create_session(wrong_key, &request(), input())
        .await
        .unwrap_err();

    assert!(matches!(error, SessionCreateError::ProfileMismatch { .. }));
    assert_eq!(binding.ensure_calls(), 0);
    assert_eq!(host.calls(), 0);
}

#[tokio::test]
async fn revision_one_is_rejected_even_when_service_and_key_match() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let mut revision_one_key = key();
    revision_one_key.profile_revision = 1;
    let sut = OpenCodeSessionCreateService::new(
        binding.clone(),
        host.clone(),
        ProfileRef {
            profile_id: ProfileId::new("opencode-baseline-inventory").expect("profile"),
            profile_revision: 1,
        },
        schema(),
    );

    let error = sut
        .create_session(revision_one_key, &request(), input())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SessionCreateError::UnsupportedProfile { .. }
    ));
    assert_eq!(binding.ensure_calls(), 0);
    assert_eq!(host.calls(), 0);
}

struct ImpossibleCommittedStore;

impl SessionBindingStore for ImpossibleCommittedStore {
    fn ensure_pending(
        &self,
        _key: &SessionBindingKey,
        _context: &SessionBindingContext,
    ) -> Result<EnsurePendingResult, BindingError> {
        Ok(EnsurePendingResult::AlreadyCommitted)
    }

    fn commit(
        &self,
        key: &SessionBindingKey,
        _expected_conversation_id: ConversationId,
        _response: &gocode_api::OpenCodeSessionInfo,
    ) -> Result<(), BindingError> {
        Err(BindingError::NotFound(key.clone()))
    }

    fn lookup(
        &self,
        _key: &SessionBindingKey,
    ) -> Result<Option<SessionBindingStatus>, BindingError> {
        Ok(None)
    }

    fn list_pending(
        &self,
        _authority: &BindingRuntimeAuthorityId,
        _limit: usize,
        _after: Option<&(NonNegativeUnixMillis, SessionBindingKey)>,
    ) -> Result<Vec<(NonNegativeUnixMillis, SessionBindingKey)>, BindingError> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn impossible_committed_state_fails_closed_before_host() {
    let host = MockHost::succeeds();
    let sut = OpenCodeSessionCreateService::new(
        ImpossibleCommittedStore,
        host.clone(),
        ProfileRef {
            profile_id: ProfileId::new("opencode-baseline-inventory").expect("profile"),
            profile_revision: 2,
        },
        schema(),
    );
    let error = sut
        .create_session(key(), &request(), input())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SessionCreateError::ImpossibleCommittedBinding { .. }
    ));
    assert_eq!(host.calls(), 0);
}

#[test]
fn fingerprint_is_deterministic_and_unambiguous() {
    let first = input();
    let mut changed = input();
    changed.workspace_id = Some("wire-workspace-2".into());

    assert_eq!(fingerprint(&first), fingerprint(&first));
    assert_ne!(fingerprint(&first), fingerprint(&changed));
}

#[test]
fn pending_listing_requires_a_nonzero_bounded_limit() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let sut = service(binding.clone(), host);
    let authority = BindingRuntimeAuthorityId::new("runtime-a").unwrap();

    assert!(matches!(
        sut.list_pending_for_recovery(&authority, 0, None),
        Err(RecoveryListError::InvalidLimit { actual: 0, .. })
    ));
    assert!(matches!(
        sut.list_pending_for_recovery(&authority, 1_001, None),
        Err(RecoveryListError::InvalidLimit { actual: 1_001, .. })
    ));
    assert!(sut.list_pending_for_recovery(&authority, 1, None).is_ok());
    assert_eq!(binding.list_calls.lock().unwrap().len(), 1);
}
