use std::sync::Arc;
use std::time::Duration;

use runne_application::commands::{CommandOutcome, CreateTaskRunInput, QueueTaskRunInput};
use runne_application::ports::{
    ApplicationCommandContext, EventStore, PrincipalId, RuntimeAuthorityId,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::service::TaskRunService;
use runne_domain::event::Actor;
use runne_domain::id::{ConversationId, IdempotencyKey, WorkspaceId};
use runne_runtime::Runtime;
use runne_runtime::config::RuntimeConfig;
use runne_runtime::controller::{ShutdownMode, ShutdownOutcome};
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;

#[path = "../../runne-store/tests/support/validated_reopen.rs"]
mod validated_reopen;

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn make_service(conn: StoreTransaction, authority: RuntimeAuthorityId) -> Arc<SqliteService> {
    Arc::new(TaskRunService::new(
        conn.clone(),
        conn.clone(),
        conn.clone(),
        authority,
    ))
}

fn default_config() -> RuntimeConfig {
    RuntimeConfig::default()
}

fn make_context(n: u8) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000000{:02x}", n)
            .parse()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("key-{}", n)).unwrap(),
        principal_id: PrincipalId("test".into()),
        actor: Actor::new("test").unwrap(),
    }
}
fn conv_id() -> ConversationId {
    "018f2e3a-7000-7000-8000-00000000000a".parse().unwrap()
}
fn ws_id() -> WorkspaceId {
    "018f2e3a-7000-7000-8000-00000000000b".parse().unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn test_full_lifecycle_sqlite() {
    let database = validated_reopen::ValidatedTestDatabase::new("lifecycle");
    let authority = RuntimeAuthorityId("test-host".into());
    let guard = available_guard();
    let (conn, identity) =
        validated_reopen::initialize_store(database.path(), authority.clone(), guard.clone())
            .unwrap();
    validated_reopen::seed_canonical_workspace(&conn, "test", ws_id());
    let svc = make_service(conn, authority.clone());
    let (handle, mut ctrl) = Runtime::start_borrowed(
        runne_runtime::TokioRuntimeContext::new_for_test(),
        svc.clone(),
        default_config(),
    )
    .unwrap();

    let o = handle
        .create_task_run(
            make_context(1),
            CreateTaskRunInput {
                conversation_id: conv_id(),
                workspace_id: ws_id(),
            },
        )
        .await
        .unwrap();
    let tr = match o {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        _ => panic!(),
    };
    handle
        .queue_task_run(
            make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr,
                expected_version: 1,
            },
        )
        .await
        .unwrap();

    let outcome = ctrl
        .shutdown(ShutdownMode::Graceful {
            timeout: Duration::from_secs(5),
        })
        .await;
    assert!(matches!(outcome, ShutdownOutcome::Quiesced));
    assert_eq!(ctrl.wait_terminated().await, ShutdownOutcome::Quiesced);
    drop(handle);
    drop(svc);

    let conn = validated_reopen::reopen_store(database.path(), identity, authority, guard).unwrap();
    let stream = conn.load_task_run(tr).unwrap();
    assert_eq!(stream.current_version, 2);
    assert_eq!(stream.events.len(), 2);
}
