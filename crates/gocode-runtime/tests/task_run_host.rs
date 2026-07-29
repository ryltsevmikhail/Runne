use std::sync::Arc;
use std::time::Duration;

use gocode_api::{
    ApiActor, ApiPrincipalId, CanonicalTaskRunState, CanonicalTerminalResult,
    CompleteTaskRunCommand, CreateTaskRunCommand, ExistingTaskRunCommand, TaskRunCommandAckKind,
    TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError, TaskRunQueryHostPort,
};
use gocode_application::ports::{EventStore, RuntimeAuthorityId};
use gocode_application::service::TaskRunService;
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use gocode_runtime::{Runtime, RuntimeTaskRunHost};
use gocode_store::store::StoreTransaction;
use tempfile::TempDir;

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-00000000000a";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-00000000000b";
const MISSING_TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-0000000000ff";

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

struct TestRuntime {
    _directory: TempDir,
    database_path: String,
    authority: RuntimeAuthorityId,
    store: StoreTransaction,
    host: RuntimeTaskRunHost<StoreTransaction>,
    controller: RuntimeController,
}

impl TestRuntime {
    fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory
            .path()
            .join("runtime.sqlite")
            .to_str()
            .unwrap()
            .to_owned();
        let authority = RuntimeAuthorityId("canonical-taskrun-test".to_owned());
        let (store, host, controller) = start_runtime(&database_path, authority.clone());
        Self {
            _directory: directory,
            database_path,
            authority,
            store,
            host,
            controller,
        }
    }

    async fn shutdown(&mut self) {
        let outcome = self
            .controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await;
        assert_eq!(outcome, ShutdownOutcome::Quiesced);
    }
}

fn start_runtime(
    database_path: &str,
    authority: RuntimeAuthorityId,
) -> (
    StoreTransaction,
    RuntimeTaskRunHost<StoreTransaction>,
    RuntimeController,
) {
    let store = StoreTransaction::open(database_path, authority.clone()).unwrap();
    let service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority,
    ));
    let (handle, controller) = Runtime::start_borrowed(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
        service,
        RuntimeConfig::default(),
    )
    .unwrap();
    let host = RuntimeTaskRunHost::new(handle, store.clone());
    (store, host, controller)
}

fn command_context(sequence: u8, key: impl Into<String>) -> TaskRunCommandContext {
    TaskRunCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000000{sequence:02x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("gocode-cli").unwrap(),
    }
}

fn create_command() -> CreateTaskRunCommand {
    CreateTaskRunCommand {
        conversation_id: CONVERSATION_ID.parse::<ConversationId>().unwrap(),
        workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn dispatches_and_reconstructs_the_complete_durable_lifecycle() {
    let mut runtime = TestRuntime::start();

    let create_context = command_context(1, "create-1");
    let created = runtime
        .host
        .create_task_run(create_context.clone(), create_command())
        .await
        .unwrap();
    assert_eq!(created.new_version, 1);
    assert_eq!(created.kind, TaskRunCommandAckKind::Created);

    let duplicate = runtime
        .host
        .create_task_run(create_context, create_command())
        .await
        .unwrap();
    assert_eq!(duplicate, created);

    let taskrun_id = created.taskrun_id;
    let queued = runtime
        .host
        .queue_task_run(
            command_context(2, "queue-1"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(queued.new_version, 2);
    assert_eq!(queued.kind, TaskRunCommandAckKind::Queued);

    let admitted = runtime
        .host
        .admit_task_run(
            command_context(3, "admit-1"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(admitted.new_version, 3);
    assert_eq!(admitted.kind, TaskRunCommandAckKind::Admitted);

    let started = runtime
        .host
        .start_attempt(
            command_context(4, "attempt-1"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 3,
            },
        )
        .await
        .unwrap();
    let attempt_id = match started.kind {
        TaskRunCommandAckKind::AttemptStarted { attempt_id } => attempt_id,
        other => panic!("expected attempt acknowledgement, got {other:?}"),
    };
    assert_eq!(started.new_version, 4);
    let running = runtime.host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(running.state, CanonicalTaskRunState::Running);
    assert_eq!(running.active_attempt_id, Some(attempt_id));

    let completed = runtime
        .host
        .complete_task_run(
            command_context(5, "complete-1"),
            CompleteTaskRunCommand {
                taskrun_id,
                expected_version: 4,
                result: CanonicalTerminalResult::Success,
            },
        )
        .await
        .unwrap();
    assert_eq!(completed.new_version, 5);
    assert_eq!(
        completed.kind,
        TaskRunCommandAckKind::Completed {
            result: CanonicalTerminalResult::Success,
        }
    );

    let snapshot = runtime.host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(snapshot.taskrun_id, taskrun_id);
    assert_eq!(snapshot.state, CanonicalTaskRunState::Succeeded);
    assert_eq!(snapshot.stream_version, 5);
    assert_eq!(snapshot.active_attempt_id, None);
    assert_eq!(
        snapshot.terminal_result,
        Some(CanonicalTerminalResult::Success)
    );

    let stream = runtime.store.load_task_run(taskrun_id).unwrap();
    assert_eq!(stream.events.len(), 5);
    assert!(
        stream
            .events
            .iter()
            .all(|event| event.actor().as_str() == "gocode-cli")
    );

    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn maps_idempotency_and_expected_version_conflicts_without_mutation() {
    let mut runtime = TestRuntime::start();
    let created = runtime
        .host
        .create_task_run(command_context(10, "create-conflict"), create_command())
        .await
        .unwrap();
    let taskrun_id = created.taskrun_id;

    runtime
        .host
        .queue_task_run(
            command_context(11, "shared-queue-key"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await
        .unwrap();

    let idempotency_conflict = runtime
        .host
        .queue_task_run(
            command_context(12, "shared-queue-key"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 3,
            },
        )
        .await;
    assert_eq!(idempotency_conflict, Err(TaskRunHostError::Conflict));

    let stale_version = runtime
        .host
        .admit_task_run(
            command_context(13, "stale-admit"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await;
    assert_eq!(stale_version, Err(TaskRunHostError::Conflict));

    let snapshot = runtime.host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(snapshot.state, CanonicalTaskRunState::Queued);
    assert_eq!(snapshot.stream_version, 2);

    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn maps_missing_queries_and_reconstructs_after_store_reopen() {
    let mut runtime = TestRuntime::start();
    let missing = MISSING_TASKRUN_ID.parse::<TaskRunId>().unwrap();
    assert_eq!(
        runtime.host.get_task_run(missing).await,
        Err(TaskRunHostError::NotFound)
    );

    let created = runtime
        .host
        .create_task_run(command_context(20, "create-reopen"), create_command())
        .await
        .unwrap();
    let taskrun_id = created.taskrun_id;
    runtime
        .host
        .queue_task_run(
            command_context(21, "queue-reopen"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await
        .unwrap();

    runtime.shutdown().await;
    drop(runtime.host);
    drop(runtime.store);

    let (reopened_store, reopened_host, mut reopened_controller) =
        start_runtime(&runtime.database_path, runtime.authority.clone());
    let snapshot = reopened_host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(snapshot.state, CanonicalTaskRunState::Queued);
    assert_eq!(snapshot.stream_version, 2);
    assert_eq!(snapshot.active_attempt_id, None);
    assert_eq!(snapshot.terminal_result, None);

    let outcome = reopened_controller
        .shutdown(ShutdownMode::Graceful {
            timeout: Duration::from_secs(5),
        })
        .await;
    assert_eq!(outcome, ShutdownOutcome::Quiesced);
    drop(reopened_host);
    drop(reopened_store);
}
