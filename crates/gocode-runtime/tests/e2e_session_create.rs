//! L2-I: exact `POST /session` compatibility flow over real SQLite adapters.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use gocode_api::{
    ApiActor, ApiCommandContext, ApiPrincipalId, CreateConversationInput, CreateConversationOutput,
    HostError, ResponseSeed, SessionHostPort,
};
use gocode_application::conversation_service::ConversationService;
use gocode_application::ports::{ConversationRepository, RuntimeAuthorityId};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_domain::id::IdempotencyKey;
use gocode_opencode_adapter_sqlite::SqliteSessionBindingStore;
use gocode_opencode_compat::profile::{
    OPENCODE_BASELINE_INVENTORY_PROFILE_ID, ProfileId, ProfileRef, SESSION_CREATE_PROFILE_REVISION,
};
use gocode_opencode_compat::{
    BindingRuntimeAuthorityId, OpenCodeCreateInput, OpenCodeSessionCreateService,
    OpenCodeSessionId, SessionBindingKey, SessionBindingStatus, SessionBindingStore,
    SessionCreateError, SessionCreateRequestContext,
};
use gocode_runtime::session_host::RuntimeConversationHost;
use gocode_security::SecretBroker;
use gocode_store::store::StoreTransaction;
use jsonschema::JSONSchema;

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-0000000000d1";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-0000000000d2";
const COMMAND_ID: &str = "018f2e3a-7000-7000-8000-0000000000d3";

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn temp_path(test_name: &str, suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gocode-phase2b-{test_name}-{}-{suffix}.sqlite",
        std::process::id()
    ))
}

fn cleanup(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

fn schema() -> Arc<JSONSchema> {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/schemas/session-info-v1.schema.json"
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

fn open_host(path: &Path) -> RuntimeConversationHost<StoreTransaction, StoreTransaction> {
    let store = StoreTransaction::open(
        path.to_str().unwrap(),
        RuntimeAuthorityId("runtime-phase2b".into()),
        available_guard(),
    )
    .unwrap();
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
    let runtime_path = temp_path("success", "runtime");
    let binding_path = temp_path("success", "binding");
    cleanup(&runtime_path);
    cleanup(&binding_path);

    let binding = SqliteSessionBindingStore::open(&binding_path).unwrap();
    let host = open_host(&runtime_path);
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

    let runtime = StoreTransaction::open(
        runtime_path.to_str().unwrap(),
        RuntimeAuthorityId("runtime-phase2b".into()),
        available_guard(),
    )
    .unwrap();
    let stream = runtime
        .load_conversation(CONVERSATION_ID.parse().unwrap())
        .unwrap();
    assert_eq!(stream.current_version, 1);
    assert_eq!(stream.events.len(), 1);

    let conn = gocode_store::schema::open_with_pragmas(runtime_path.to_str().unwrap()).unwrap();
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
    cleanup(&runtime_path);
    cleanup(&binding_path);
}

#[tokio::test]
async fn pending_binding_recovers_after_host_commit_before_binding_commit() {
    let runtime_path = temp_path("recovery", "runtime");
    let binding_path = temp_path("recovery", "binding");
    cleanup(&runtime_path);
    cleanup(&binding_path);

    let binding = SqliteSessionBindingStore::open(&binding_path).unwrap();
    let failing_host = FailAfterDurableHost {
        inner: open_host(&runtime_path),
    };
    let failing_service =
        OpenCodeSessionCreateService::new(binding.clone(), failing_host, profile(), schema());
    let first = failing_service
        .create_session(key(), &request(), wire_input())
        .await;
    assert!(matches!(
        first,
        Err(SessionCreateError::Host(HostError::StorageFailure))
    ));
    assert!(matches!(
        binding.lookup(&key()).unwrap(),
        Some(SessionBindingStatus::Pending { .. })
    ));
    drop(failing_service);
    drop(binding);

    let reopened_binding = SqliteSessionBindingStore::open(&binding_path).unwrap();
    let recovered_service = OpenCodeSessionCreateService::new(
        reopened_binding.clone(),
        open_host(&runtime_path),
        profile(),
        schema(),
    );
    let response = recovered_service.recover_pending(key()).await.unwrap();
    let retry = recovered_service
        .create_session(key(), &request(), wire_input())
        .await
        .unwrap();
    assert_eq!(response, retry);
    assert!(matches!(
        reopened_binding.lookup(&key()).unwrap(),
        Some(SessionBindingStatus::Committed { .. })
    ));

    let runtime = StoreTransaction::open(
        runtime_path.to_str().unwrap(),
        RuntimeAuthorityId("runtime-phase2b".into()),
        available_guard(),
    )
    .unwrap();
    assert_eq!(
        runtime
            .load_conversation(CONVERSATION_ID.parse().unwrap())
            .unwrap()
            .events
            .len(),
        1
    );

    drop(runtime);
    drop(recovered_service);
    drop(reopened_binding);
    cleanup(&runtime_path);
    cleanup(&binding_path);
}

#[test]
fn concurrent_retries_commit_one_binding_conversation_event_and_receipt() {
    let runtime_path = temp_path("concurrent", "runtime");
    let binding_path = temp_path("concurrent", "binding");
    cleanup(&runtime_path);
    cleanup(&binding_path);

    let binding_one = SqliteSessionBindingStore::open(&binding_path).unwrap();
    let binding_two = SqliteSessionBindingStore::open(&binding_path).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let service_one = OpenCodeSessionCreateService::new(
        binding_one,
        BarrierHost {
            inner: open_host(&runtime_path),
            barrier: barrier.clone(),
        },
        profile(),
        schema(),
    );
    let service_two = OpenCodeSessionCreateService::new(
        binding_two,
        BarrierHost {
            inner: open_host(&runtime_path),
            barrier,
        },
        profile(),
        schema(),
    );

    let first = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(service_one.create_session(key(), &request(), wire_input()))
    });
    let second = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(service_two.create_session(key(), &request(), wire_input()))
    });
    let first = first.join().unwrap().unwrap();
    let second = second.join().unwrap().unwrap();
    assert_eq!(first, second);

    let runtime_conn =
        gocode_store::schema::open_with_pragmas(runtime_path.to_str().unwrap()).unwrap();
    let runtime_counts: (i64, i64) = runtime_conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM events WHERE aggregate_type = 2),
                (SELECT COUNT(*) FROM command_receipts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(runtime_counts, (1, 1));
    let binding_conn =
        gocode_opencode_adapter_sqlite::schema::open_with_pragmas(&binding_path).unwrap();
    let binding_count: i64 = binding_conn
        .query_row(
            "SELECT COUNT(*) FROM session_bindings WHERE status = 'committed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(binding_count, 1);

    drop(binding_conn);
    drop(runtime_conn);
    cleanup(&runtime_path);
    cleanup(&binding_path);
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_writer_contention_does_not_block_unrelated_tokio_timers() {
    let runtime_path = temp_path("async-contention", "runtime");
    cleanup(&runtime_path);
    let host = open_host(&runtime_path);
    let lock_barrier = Arc::new(Barrier::new(2));
    let lock_thread_barrier = lock_barrier.clone();
    let lock_path = runtime_path.clone();
    let (release_lock, await_release) = std::sync::mpsc::channel();
    let lock_thread = std::thread::spawn(move || {
        let conn = gocode_store::schema::open_with_pragmas(lock_path.to_str().unwrap()).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        lock_thread_barrier.wait();
        await_release
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("Tokio worker did not make progress while SQLite was locked");
        conn.execute_batch("ROLLBACK").unwrap();
    });
    lock_barrier.wait();

    let context = request().api_context;
    let input = CreateConversationInput {
        conversation_id: CONVERSATION_ID.parse().unwrap(),
        workspace_id: WORKSPACE_ID.parse().unwrap(),
        command_id: COMMAND_ID.parse().unwrap(),
        idempotency_key: IdempotencyKey::new("async-contention").unwrap(),
    };
    let host_call = tokio::spawn(async move { host.create_conversation(&context, input).await });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(
        !host_call.is_finished(),
        "SQLite contention blocked the current Tokio worker"
    );
    release_lock.send(()).unwrap();

    host_call.await.unwrap().unwrap();
    lock_thread.join().unwrap();
    cleanup(&runtime_path);
}
