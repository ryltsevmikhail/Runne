use std::sync::Arc;
use std::time::Duration;

use gocode_application::commands::{CommandOutcome, CreateTaskRunInput, QueueTaskRunInput};
use gocode_application::ports::{
    ApplicationCommandContext, EventStore, PrincipalId, RuntimeAuthorityId,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::service::TaskRunService;
use gocode_domain::event::Actor;
use gocode_domain::id::{ConversationId, IdempotencyKey, WorkspaceId};
use gocode_runtime::Runtime;
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{ShutdownMode, ShutdownOutcome};
use gocode_security::SecretBroker;
use gocode_store::store::StoreTransaction;

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn make_service(db: &str, authority: RuntimeAuthorityId) -> Arc<SqliteService> {
    let conn = StoreTransaction::open(db, authority.clone(), available_guard()).unwrap();
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

fn db_path(name: &str) -> String {
    let mut d = std::env::temp_dir();
    d.push(format!("gocode-rt-l2i-{}.sqlite", name));
    d.to_str().unwrap().to_string()
}

#[tokio::test(flavor = "current_thread")]
async fn test_full_lifecycle_sqlite() {
    let db = db_path("lifecycle");
    let wal = format!("{}-wal", db);
    let shm = format!("{}-shm", db);
    for p in [db.as_str(), wal.as_str(), shm.as_str()] {
        let _ = std::fs::remove_file(p);
    }

    let svc = make_service(&db, RuntimeAuthorityId("test-host".into()));
    let (handle, mut ctrl) = Runtime::start_borrowed(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
        svc,
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

    let conn = StoreTransaction::open(
        &db,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let stream = conn.load_task_run(tr).unwrap();
    assert_eq!(stream.current_version, 2);
    assert_eq!(stream.events.len(), 2);

    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(&shm);
}
