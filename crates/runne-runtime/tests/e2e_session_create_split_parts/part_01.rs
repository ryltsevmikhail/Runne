use std::sync::{Arc, Barrier};

use runne_api::{
    ApiActor, ApiCommandContext, ApiPrincipalId, CreateConversationInput, CreateConversationOutput,
    HostError, ResponseSeed, SessionHostPort,
};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{ConversationRepository, RuntimeAuthorityId};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::id::IdempotencyKey;
use runne_opencode_adapter_sqlite::SqliteSessionBindingStore;
use runne_opencode_compat::profile::{
    OPENCODE_BASELINE_INVENTORY_PROFILE_ID, ProfileId, ProfileRef, SESSION_CREATE_PROFILE_REVISION,
};
use runne_opencode_compat::{
    BindingRuntimeAuthorityId, OpenCodeCreateInput, OpenCodeSessionCreateService,
    OpenCodeSessionId, SessionBindingKey, SessionBindingStatus, SessionBindingStore,
    SessionCreateError, SessionCreateRequestContext,
};
use runne_runtime::session_host::RuntimeConversationHost;
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;
use jsonschema::JSONSchema;

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-0000000000d1";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-0000000000d2";
const COMMAND_ID: &str = "018f2e3a-7000-7000-8000-0000000000d3";

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn schema() -> Arc<JSONSchema> {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/schemas/session-info-v1.schema.json"
    ))
    .unwrap();
    Arc::new(
        JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&value)
            .unwrap(),
    )
}

fn profile() -> ProfileRef {
    ProfileRef {
        profile_id: ProfileId::new(OPENCODE_BASELINE_INVENTORY_PROFILE_ID).unwrap(),
        profile_revision: SESSION_CREATE_PROFILE_REVISION,
    }
}

fn key() -> SessionBindingKey {
    SessionBindingKey {
        session_id: OpenCodeSessionId::new("ses_phase2b_e2e").unwrap(),
        profile_id: ProfileId::new(OPENCODE_BASELINE_INVENTORY_PROFILE_ID).unwrap(),
        profile_revision: SESSION_CREATE_PROFILE_REVISION,
        runtime_authority_id: BindingRuntimeAuthorityId::new("runtime-phase2b").unwrap(),
    }
}

fn request() -> SessionCreateRequestContext {
    SessionCreateRequestContext {
        conversation_id: CONVERSATION_ID.parse().unwrap(),
        workspace_id: WORKSPACE_ID.parse().unwrap(),
        command_id: COMMAND_ID.parse().unwrap(),
        idempotency_key: IdempotencyKey::new("phase2b-session-create").unwrap(),
        api_context: ApiCommandContext {
            principal: ApiPrincipalId::new("phase2b-principal").unwrap(),
            actor: ApiActor::new("phase2b-actor").unwrap(),
            response_seed: ResponseSeed {
                project_id: "project-phase2b".into(),
                directory: "/workspace/phase2b".into(),
                path: Some("/workspace/phase2b".into()),
                version: "2.0.0".into(),
                workspace_id: Some("workspace-wire-id".into()),
            },
        },
    }
}

fn wire_input() -> OpenCodeCreateInput {
    OpenCodeCreateInput {
        title: Some("Phase 2b session".into()),
        workspace_id: Some("workspace-wire-id".into()),
        parent_id: None,
        agent: None,
        model: None,
        metadata: None,
        permission: None,
    }
}

fn runtime_authority() -> RuntimeAuthorityId {
    RuntimeAuthorityId("runtime-phase2b".into())
}

struct RuntimeFixture {
    _database: validated_reopen::ValidatedTestDatabase,
    database_path: String,
    identity: validated_reopen::MainDatabaseIdentity,
}

impl RuntimeFixture {
    fn new(test_name: &str) -> (Self, StoreTransaction) {
        let database = validated_reopen::ValidatedTestDatabase::new(test_name);
        let database_path = database.path().to_owned();
        let (store, identity) = validated_reopen::initialize_store(
            &database_path,
            runtime_authority(),
            available_guard(),
        )
        .unwrap();
        (
            Self {
                _database: database,
                database_path,
                identity,
            },
            store,
        )
    }

    fn reopen_store(&self) -> StoreTransaction {
        validated_reopen::reopen_store(
            &self.database_path,
            self.identity,
            runtime_authority(),
            available_guard(),
        )
        .unwrap()
    }
}

fn open_host(store: StoreTransaction) -> RuntimeConversationHost<StoreTransaction, StoreTransaction> {
    RuntimeConversationHost::new(ConversationService::new(
        store.clone(),
        store.clone(),
        store.runtime_authority_id().clone(),
    ))
}

struct FailAfterDurableHost<H> {
    inner: H,
}

struct BarrierHost<H> {
    inner: H,
    barrier: Arc<Barrier>,
}

impl<H> SessionHostPort for BarrierHost<H>
where
    H: SessionHostPort + Send + Sync,
{
    async fn create_conversation(
        &self,
        context: &ApiCommandContext,
        input: CreateConversationInput,
    ) -> Result<CreateConversationOutput, HostError> {
        self.barrier.wait();
        self.inner.create_conversation(context, input).await
    }
}

impl<H> SessionHostPort for FailAfterDurableHost<H>
where
    H: SessionHostPort + Send + Sync,
{
    async fn create_conversation(
        &self,
        context: &ApiCommandContext,
        input: CreateConversationInput,
    ) -> Result<CreateConversationOutput, HostError> {
        self.inner.create_conversation(context, input).await?;
        Err(HostError::StorageFailure)
    }
}

#[tokio::test]
async fn session_create_commits_binding_and_only_a_conversation_stream() {
    let (runtime_fixture, runtime_store) = RuntimeFixture::new("session-create-success");
    let binding_directory = tempfile::tempdir().unwrap();
    let binding_path = { let daemon = binding_directory.path().join("runne-daemon"); std::fs::create_dir_all(&daemon).unwrap(); daemon.join("binding.sqlite") };

    let binding = SqliteSessionBindingStore::open(&binding_path).unwrap();
    let host = open_host(runtime_store);
    let service = OpenCodeSessionCreateService::new(binding.clone(), host, profile(), schema());

    let response = service
        .create_session(key(), &request(), wire_input())
        .await
        .unwrap();

    assert_eq!(response.as_value()["id"], "ses_phase2b_e2e");
    assert_eq!(response.as_value()["title"], "Phase 2b session");
    assert!(matches!(
        binding.lookup(&key()).unwrap(),
        Some(SessionBindingStatus::Committed { .. })
    ));

    let runtime = runtime_fixture.reopen_store();
    let stream = runtime
        .load_conversation(CONVERSATION_ID.parse().unwrap())
        .unwrap();
    assert_eq!(stream.current_version, 1);
    assert_eq!(stream.events.len(), 1);

    let conn = validated_reopen::open_validated_connection(
        &runtime_fixture.database_path,
        runtime_fixture.identity,
    )
    .unwrap();
    let counts: (i64, i64, i64) = conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM events WHERE aggregate_type = 1),
                (SELECT COUNT(*) FROM events WHERE aggregate_type = 2),
                (SELECT COUNT(*) FROM command_receipts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (0, 1, 1));

    drop(conn);
    drop(runtime);
    drop(service);
    drop(binding);
}
