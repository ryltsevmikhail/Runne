use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runne_application::commands::{CancelTaskRunInput, CommandOutcome, SubmitTaskRunInput};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ApplicationCommandContext, CompleteQueuedCancellationInput, EventStore, EventStoreError,
    PrincipalId, RuntimeAuthorityId, TaskRunQueueCandidate, TaskRunQueueScanPage,
};
use runne_application::service::TaskRunService;
use runne_domain::event::Actor;
use runne_domain::id::{ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
use runne_domain::task_run::{TaskRunEvent, TaskRunInput, TaskRunState};
use runne_provider::ProviderFuture;
use runne_runtime::config::RuntimeConfig;
use runne_runtime::controller::{ShutdownMode, ShutdownOutcome};
use runne_runtime::{AutomaticTaskRunError, AutomaticTaskRunService, Runtime};
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;
use tokio::sync::Notify;

#[path = "../../runne-store/tests/support/validated_reopen.rs"]
mod validated_reopen;

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

struct HeldCancellationService {
    store: StoreTransaction,
    taskruns: Arc<SqliteService>,
    taskrun_id: Mutex<Option<TaskRunId>>,
    settlement_starts: AtomicUsize,
    active_settlements: AtomicUsize,
    released: AtomicBool,
    settlement_entered: Notify,
    release_settlement: Notify,
}

impl HeldCancellationService {
    fn candidate(
        &self,
        taskrun_id: TaskRunId,
    ) -> Result<Option<TaskRunQueueCandidate>, EventStoreError> {
        let stream = self
            .store
            .load_task_run(taskrun_id)
            .map_err(|_| EventStoreError::Unavailable)?;
        let task = runne_domain::task_run::TaskRun::replay(&stream.events)
            .map_err(|_| EventStoreError::CorruptData)?;
        Ok(
            (task.state() == TaskRunState::Cancelling).then_some(TaskRunQueueCandidate {
                taskrun_id,
                current_version: stream.current_version,
            }),
        )
    }
}
impl AutomaticTaskRunService for HeldCancellationService {
    fn scan_queued(
        &self,
        _after: Option<TaskRunId>,
        _limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        Ok(TaskRunQueueScanPage {
            candidates: Vec::new(),
            next_cursor: None,
            reached_end: true,
            examined: 0,
        })
    }

    fn scan_pending_cancellations(
        &self,
        _after: Option<TaskRunId>,
        _limit: usize,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        let candidates = self
            .taskrun_id
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|id| self.candidate(*id).ok().flatten())
            .into_iter()
            .collect::<Vec<_>>();
        Ok(TaskRunQueueScanPage {
            next_cursor: candidates.last().map(|item| item.taskrun_id),
            reached_end: true,
            examined: usize::from(!candidates.is_empty()),
            candidates,
        })
    }

    fn execute_queued(
        &self,
        _candidate: TaskRunQueueCandidate,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        Box::pin(async { Err(AutomaticTaskRunError::Unavailable) })
    }

    fn complete_queued_cancellation(
        &self,
        taskrun_id: TaskRunId,
        expected_version: u64,
    ) -> ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        Box::pin(async move {
            self.settlement_starts.fetch_add(1, Ordering::SeqCst);
            self.active_settlements.fetch_add(1, Ordering::SeqCst);
            self.settlement_entered.notify_waiters();
            loop {
                let notified = self.release_settlement.notified();
                if self.released.load(Ordering::SeqCst) {
                    break;
                }
                notified.await;
            }
            self.active_settlements.fetch_sub(1, Ordering::SeqCst);
            let context = command_context(4);
            self.taskruns
                .complete_queued_cancellation(
                    &context,
                    CompleteQueuedCancellationInput {
                        taskrun_id,
                        expected_version,
                    },
                    &self.store,
                )
                .map(|_| ())
                .map_err(|_| AutomaticTaskRunError::Uncertain)
        })
    }
}
fn command_context(sequence: u8) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000000{sequence:02x}")
            .parse()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("cancel-reply-{sequence}")).unwrap(),
        principal_id: PrincipalId("test".into()),
        actor: Actor::new("test").unwrap(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn public_cancel_replies_while_scanner_settlement_is_held() {
    let database = validated_reopen::ValidatedTestDatabase::new("cancel-reply");
    let authority = RuntimeAuthorityId("cancel-reply-test".into());
    let guard = Arc::new(SecretBroker::new().prohibited_content_guard());
    let (store, _) =
        validated_reopen::initialize_store(database.path(), authority.clone(), guard.clone())
            .unwrap();
    validated_reopen::seed_canonical_workspace(
        &store,
        "test",
        "018f2e3a-7000-7000-8000-00000000000b"
            .parse::<WorkspaceId>()
            .unwrap(),
    );
    let taskruns = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority.clone(),
    ));
    let text: Arc<dyn ConversationTextCommandService> = Arc::new(ConversationTextService::new(
        store.clone(),
        store.clone(),
        authority,
        guard,
    ));
    let auto = Arc::new(HeldCancellationService {
        store: store.clone(),
        taskruns: Arc::clone(&taskruns),
        taskrun_id: Mutex::new(None),
        settlement_starts: AtomicUsize::new(0),
        active_settlements: AtomicUsize::new(0),
        released: AtomicBool::new(false),
        settlement_entered: Notify::new(),
        release_settlement: Notify::new(),
    });
    let (handle, mut controller) = Runtime::start_borrowed_with_automatic_taskruns(
        runne_runtime::TokioRuntimeContext::new_for_test(),
        taskruns,
        text,
        None,
        auto.clone(),
        RuntimeConfig::default(),
    )
    .unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-00000000000a".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-00000000000b".parse().unwrap();
    let conversation_context = command_context(10);
    ConversationService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId("cancel-reply-test".into()),
    )
    .create_from_application(
        &conversation_context,
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id,
            command_id: conversation_context.command_id,
            idempotency_key: conversation_context.idempotency_key.clone(),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let submitted = handle
        .submit_task_run(
            command_context(1),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input: TaskRunInput::new("prompt for queued cancellation".into()).unwrap(),
            },
        )
        .await
        .unwrap();
    let taskrun_id = match submitted {
        CommandOutcome::TaskRunSubmitted {
            taskrun_id,
            new_version: 2,
        } => taskrun_id,
        other => panic!("unexpected submit outcome: {other:?}"),
    };
    *auto.taskrun_id.lock().unwrap() = Some(taskrun_id);

    let cancel_handle = handle.clone();
    let mut cancel = tokio::spawn(async move {
        cancel_handle
            .cancel_task_run(
                command_context(3),
                CancelTaskRunInput {
                    taskrun_id,
                    expected_version: 2,
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let notified = auto.settlement_entered.notified();
            if auto.settlement_starts.load(Ordering::SeqCst) > 0 {
                break;
            }
            notified.await;
        }
    })
    .await
    .expect("the durable cancellation scanner starts settlement");
    let prompt_reply = tokio::time::timeout(Duration::from_millis(500), &mut cancel).await;
    auto.released.store(true, Ordering::SeqCst);
    auto.release_settlement.notify_waiters();
    let cancel_result = match prompt_reply {
        Ok(joined) => Some(joined.expect("cancel request task completes").unwrap()),
        Err(_) => {
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut cancel).await;
            None
        }
    };
    assert!(cancel_result.is_some(), "cancel reply waits on settlement");
    let cancel_result = cancel_result.unwrap();
    assert!(matches!(
        cancel_result,
        CommandOutcome::TaskRunCancellationRequested { taskrun_id: id, .. }
            if id == taskrun_id
    ));
    assert_eq!(auto.settlement_starts.load(Ordering::SeqCst), 1);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let stream = auto.store.load_task_run(taskrun_id).unwrap();
            if matches!(
                stream.events.last().map(|event| event.payload()),
                Some(TaskRunEvent::CancellationCompleted)
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("scanner completes the queued cancellation after release");

    assert_eq!(auto.settlement_starts.load(Ordering::SeqCst), 1);
    assert_eq!(auto.active_settlements.load(Ordering::SeqCst), 0);
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
}
