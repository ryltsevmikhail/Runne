// Shared SQLite runtime harness. Imports and constants live in this file;
// both split parts are included into one test crate module.

use std::sync::Arc;
use std::time::Duration;

use runne_api::{
    ApiActor, ApiPrincipalId, CanonicalTaskRunState, CreateConversationInput,
    ExistingTaskRunCommand, SubmitTaskRunCommand, TaskRunCommandAck, TaskRunCommandAckKind,
    TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError, TaskRunQueryHostPort,
};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{
    ApplicationCommandContext, EventStore, PrincipalId, RuntimeAuthorityId,
};
use runne_application::service::TaskRunService;
use runne_domain::event::Actor;
use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use runne_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use runne_runtime::config::RuntimeConfig;
use runne_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use runne_runtime::{Runtime, RuntimeTaskRunHost, TokioRuntimeContext};
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-00000000000a";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-00000000000b";
const OTHER_WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-00000000000c";

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

struct SubmitRuntime {
    store: StoreTransaction,
    host: RuntimeTaskRunHost<StoreTransaction>,
    controller: RuntimeController,
}

impl SubmitRuntime {
    fn start() -> Self {
        let database = validated_reopen::ValidatedTestDatabase::new("task-run-submit");
        let authority = RuntimeAuthorityId("canonical-taskrun-submit-test".to_owned());
        let (store, _identity) = validated_reopen::initialize_store(
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
        let conversation_context = ApplicationCommandContext {
            command_id: "018f2e3a-7000-7000-8000-0000000000d1".parse().unwrap(),
            idempotency_key: IdempotencyKey::new("fixture-submit-conversation").unwrap(),
            principal_id: PrincipalId("local-owner".into()),
            actor: Actor::new("runtime-submit-fixture").unwrap(),
        };
        ConversationService::new(store.clone(), store.clone(), authority.clone())
            .create_from_application(
                &conversation_context,
                CreateConversationInput {
                    conversation_id: CONVERSATION_ID.parse().unwrap(),
                    workspace_id: WORKSPACE_ID.parse().unwrap(),
                    command_id: conversation_context.command_id,
                    idempotency_key: conversation_context.idempotency_key.clone(),
                    scope: runne_api::ConversationContextScope::Workspace,
                },
            )
            .unwrap();
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
        let host = RuntimeTaskRunHost::new(handle, store.clone());
        Self {
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
        assert_eq!(
            self.controller.wait_terminated().await,
            ShutdownOutcome::Quiesced
        );
    }
}

fn command_context(sequence: u8, key: impl Into<String>) -> TaskRunCommandContext {
    TaskRunCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000001{sequence:02x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("runne-cli").unwrap(),
    }
}

fn submit_command(workspace: &str) -> SubmitTaskRunCommand {
    SubmitTaskRunCommand {
        conversation_id: CONVERSATION_ID.parse::<ConversationId>().unwrap(),
        workspace_id: workspace.parse::<WorkspaceId>().unwrap(),
        input: runne_domain::task_run::TaskRunInput::new("test prompt".to_owned()).unwrap(),
    }
}

fn assert_submitted_batch(runtime: &SubmitRuntime, ack: &TaskRunCommandAck) {
    assert_eq!(ack.new_version, 2);
    assert_eq!(ack.kind, TaskRunCommandAckKind::Submitted);

    let stream = runtime.store.load_task_run(ack.taskrun_id).unwrap();
    assert_eq!(stream.events.len(), 2, "submit commits exactly two events");
    assert_eq!(stream.events[0].sequence(), 1);
    assert!(matches!(
        stream.events[0].payload(),
        TaskRunEvent::TaskRunSubmitted { input, .. } if input.prompt() == "test prompt"
    ));
    assert_eq!(stream.events[1].sequence(), 2);
    assert_eq!(stream.events[1].payload(), &TaskRunEvent::TaskRunQueued);
    assert_eq!(
        stream.events[1].causation_id(),
        Some(stream.events[0].event_id()),
        "queued event causally chains to the created event"
    );
    assert!(
        stream
            .events
            .iter()
            .all(|event| event.actor().as_str() == "runne-cli")
    );

    let replayed = TaskRun::replay(&stream.events).expect("committed batch must replay");
    assert_eq!(replayed.state(), TaskRunState::Queued);
}

async fn query_state(
    runtime: &SubmitRuntime,
    taskrun_id: runne_domain::id::TaskRunId,
) -> (CanonicalTaskRunState, u64) {
    let snapshot = runtime.host.get_task_run(taskrun_id).await.unwrap();
    (snapshot.state, snapshot.stream_version)
}
