// Shared SQLite restart/fault harness for X2 phase 3 evidence tests.
// Included into one test crate module together with `tests.rs`.

use std::sync::Arc;
use std::time::Duration;

use runne_api::{
    ApiActor, ApiPrincipalId, CanonicalTaskRunState, SubmitTaskRunCommand, TaskRunCommandAck,
    TaskRunCommandAckKind, TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError,
    TaskRunQueryHostPort,
};
use runne_application::ports::{EventStore, RuntimeAuthorityId};
use runne_application::service::TaskRunService;
use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use runne_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use runne_runtime::config::RuntimeConfig;
use runne_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use runne_runtime::{Runtime, RuntimeTaskRunHost, TokioRuntimeContext};
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-00000000001a";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-00000000001b";

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

/// A restartable runtime over one durable SQLite store. `restart` performs a
/// genuine runtime shutdown and a validated store reopen — the same path a
/// daemon crash-and-recovery takes, without killing this test process.
struct RestartableRuntime {
    database: validated_reopen::ValidatedTestDatabase,
    identity: validated_reopen::MainDatabaseIdentity,
    authority: RuntimeAuthorityId,
    host: Option<RuntimeTaskRunHost<StoreTransaction>>,
    store: Option<StoreTransaction>,
    controller: Option<RuntimeController>,
}

impl RestartableRuntime {
    fn start() -> Self {
        let database = validated_reopen::ValidatedTestDatabase::new("task-run-recovery");
        let authority = RuntimeAuthorityId("canonical-taskrun-recovery-test".to_owned());
        let (store, identity) = validated_reopen::initialize_store(
            database.path(),
            authority.clone(),
            Arc::new(SecretBroker::new().prohibited_content_guard()),
        )
        .unwrap();
        validated_reopen::seed_canonical_workspace(
            &store,
            "local-owner",
            WORKSPACE_ID.parse().unwrap(),
        );
        let (host, controller) = Self::spawn(store.clone(), authority.clone());
        Self {
            database,
            identity,
            authority,
            host: Some(host),
            store: Some(store),
            controller: Some(controller),
        }
    }

    fn spawn(
        store: StoreTransaction,
        authority: RuntimeAuthorityId,
    ) -> (RuntimeTaskRunHost<StoreTransaction>, RuntimeController) {
        let service: Arc<SqliteService> = Arc::new(TaskRunService::new(
            store.clone(),
            store.clone(),
            store.clone(),
            authority,
        ));
        let (handle, controller) = Runtime::start_borrowed(
            TokioRuntimeContext::new_for_test(),
            service,
            RuntimeConfig::default(),
        )
        .unwrap();
        (RuntimeTaskRunHost::new(handle, store.clone()), controller)
    }

    fn host(&self) -> &RuntimeTaskRunHost<StoreTransaction> {
        self.host.as_ref().unwrap()
    }

    fn store(&self) -> &StoreTransaction {
        self.store.as_ref().unwrap()
    }

    /// Genuine fault: graceful runtime shutdown (all ingress-accepted work
    /// committed), then a validated reopen — the real restart path.
    async fn restart(&mut self) {
        let mut controller = self.controller.take().unwrap();
        let outcome = controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await;
        assert_eq!(outcome, ShutdownOutcome::Quiesced);
        assert_eq!(
            controller.wait_terminated().await,
            ShutdownOutcome::Quiesced
        );

        let reopened = validated_reopen::reopen_store(
            self.database.path(),
            self.identity,
            self.authority.clone(),
            Arc::new(SecretBroker::new().prohibited_content_guard()),
        )
        .expect("validated reopen must succeed after restart");
        let (host, controller) = Self::spawn(reopened.clone(), self.authority.clone());
        self.store = Some(reopened);
        self.host = Some(host);
        self.controller = Some(controller);
    }

    async fn shutdown(&mut self) {
        let mut controller = self.controller.take().expect("runtime still running");
        let outcome = controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await;
        assert_eq!(outcome, ShutdownOutcome::Quiesced);
        assert_eq!(
            controller.wait_terminated().await,
            ShutdownOutcome::Quiesced
        );
        self.host = None;
        self.store = None;
    }
}

fn command_context(sequence: u8, key: impl Into<String>) -> TaskRunCommandContext {
    TaskRunCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000002{sequence:02x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("runne-cli").unwrap(),
    }
}

fn submit_command() -> SubmitTaskRunCommand {
    SubmitTaskRunCommand {
        conversation_id: CONVERSATION_ID.parse::<ConversationId>().unwrap(),
        workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
    }
}

fn assert_submitted_stream(store: &StoreTransaction, ack: &TaskRunCommandAck) {
    assert_eq!(ack.new_version, 2);
    assert_eq!(ack.kind, TaskRunCommandAckKind::Submitted);
    let stream = store.load_task_run(ack.taskrun_id).unwrap();
    assert_eq!(stream.events.len(), 2, "exactly Created + Queued");
    assert_eq!(stream.events[0].payload(), &TaskRunEvent::TaskRunCreated);
    assert_eq!(stream.events[1].payload(), &TaskRunEvent::TaskRunQueued);
    let replayed = TaskRun::replay(&stream.events).unwrap();
    assert_eq!(replayed.state(), TaskRunState::Queued);
}

async fn query_state(
    host: &RuntimeTaskRunHost<StoreTransaction>,
    taskrun_id: runne_domain::id::TaskRunId,
) -> (CanonicalTaskRunState, u64) {
    let snapshot = host.get_task_run(taskrun_id).await.unwrap();
    (snapshot.state, snapshot.stream_version)
}
