use crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns;
use runne_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
    LegacySubmitTaskRunInput, SubmitTaskRunInput,
};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, ExecutionNodeId, PrincipalId,
    RuntimeAuthorityId, TaskRunQueueCandidate,
};
use runne_application::service::TaskRunService;
use runne_domain::event::Actor;
use runne_domain::id::{IdempotencyKey, TaskRunId};
use runne_domain::message::MessageText;
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunError;
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;
use std::sync::{Arc, atomic::AtomicU64};

const AUTHORITY: &str = "nm06-gate";

fn context(tail: u8, operation: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000000{tail:02x}")
            .parse()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(operation).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("queue-gate-test").unwrap(),
    }
}

#[tokio::test]
async fn queued_taskrun_waits_for_existing_conversation_generation() {
    let super::nm06_delivery_gate_fixture::Composed {
        directory: _directory,
        db_path: path,
        store,
        conversation_id,
        ..
    } = super::nm06_delivery_gate_fixture::composition_with(
        runne_domain::conversation::ConversationContextScope::Workspace,
        true,
    );
    let conversation = runne_domain::conversation::Conversation::replay(
        &store.load_conversation(conversation_id).unwrap().events,
    )
    .unwrap();
    let workspace_id = conversation.workspace_id;

    let taskruns = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
    ));
    let taskrun_id = match taskruns
        .submit_task_run(
            &context(4, "queue-gate-submit"),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input: runne_domain::task_run::TaskRunInput::new("queued prompt".into()).unwrap(),
            },
        )
        .unwrap()
    {
        runne_application::commands::CommandOutcome::TaskRunSubmitted {
            taskrun_id,
            new_version,
        } => {
            assert_eq!(new_version, 2);
            taskrun_id
        }
        other => panic!("unexpected submit result: {other:?}"),
    };

    let guard = Arc::new(SecretBroker::new().prohibited_content_guard());
    let text = Arc::new(ConversationTextService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
        guard,
    ));
    let active_input = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("ordinary generation").unwrap(),
    };
    let generation_context = context(5, "queue-gate-active-generation");
    let started = text
        .begin(&generation_context, active_input.clone())
        .unwrap();
    let worker = DaemonAutomaticTaskRuns::new(
        store.clone(),
        taskruns,
        text.clone() as Arc<dyn ConversationTextCommandService>,
        None,
        ExecutionNodeId("queue-gate-node".into()),
        1,
        Arc::new(AtomicU64::new(1)),
    );
    let candidate = TaskRunQueueCandidate {
        taskrun_id,
        current_version: 2,
    };
    assert_eq!(
        worker.submit_selection_before_claim(candidate),
        Err(AutomaticTaskRunError::Unavailable),
        "an active writer leaves the accepted TaskRun queued"
    );
    assert_queued_without_claim(&store, taskrun_id, &path);

    text.finish(
        &generation_context,
        FinishConversationTextInput {
            original: active_input,
            started,
            completion: ConversationTextCompletion::AssistantText(
                MessageText::new("ordinary response").unwrap(),
            ),
        },
    )
    .unwrap();
    assert_eq!(
        worker.submit_selection_before_claim(candidate),
        Ok((None, None)),
        "the exact queued run becomes eligible after the writer settles"
    );
    assert_queued_without_claim(&store, taskrun_id, &path);
    assert_eq!(
        worker.execute_one(candidate).await,
        Err(AutomaticTaskRunError::Unavailable),
        "the actual worker recognizes a v2 submission without a requested model before needing a provider"
    );
    assert_queued_without_claim(&store, taskrun_id, &path);
}

#[tokio::test]
async fn legacy_promptless_v1_remains_queued_without_worker_claim() {
    let super::nm06_delivery_gate_fixture::Composed {
        directory: _directory,
        db_path: path,
        store,
        conversation_id,
        ..
    } = super::nm06_delivery_gate_fixture::composition_with(
        runne_domain::conversation::ConversationContextScope::Workspace,
        true,
    );
    let conversation = runne_domain::conversation::Conversation::replay(
        &store.load_conversation(conversation_id).unwrap().events,
    )
    .unwrap();
    let taskruns = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
    ));
    let taskrun_id = match taskruns
        .submit_task_run_legacy(
            &context(6, "queue-gate-v1-submit"),
            LegacySubmitTaskRunInput {
                conversation_id,
                workspace_id: conversation.workspace_id,
            },
        )
        .unwrap()
    {
        runne_application::commands::CommandOutcome::TaskRunSubmitted {
            taskrun_id,
            new_version: 2,
        } => taskrun_id,
        other => panic!("unexpected legacy submit result: {other:?}"),
    };
    let guard = Arc::new(SecretBroker::new().prohibited_content_guard());
    let text = Arc::new(ConversationTextService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(AUTHORITY.into()),
        guard,
    ));
    let worker = DaemonAutomaticTaskRuns::new(
        store.clone(),
        taskruns,
        text as Arc<dyn ConversationTextCommandService>,
        None,
        ExecutionNodeId("queue-gate-node".into()),
        1,
        Arc::new(AtomicU64::new(1)),
    );
    let candidate = TaskRunQueueCandidate {
        taskrun_id,
        current_version: 2,
    };
    assert_eq!(
        worker.execute_one(candidate).await,
        Err(AutomaticTaskRunError::Uncertain),
        "the legacy snapshot lacks v2 immutable input and remains ineligible before claim"
    );
    assert_queued_without_claim(&store, taskrun_id, &path);
}

fn assert_queued_without_claim(
    store: &StoreTransaction,
    taskrun_id: TaskRunId,
    path: &std::path::Path,
) {
    use runne_application::ports::EventStore;
    let stream = store.load_task_run(taskrun_id).unwrap();
    assert_eq!(stream.current_version, 2);
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(&stream.events)
            .unwrap()
            .state(),
        runne_domain::task_run::TaskRunState::Queued
    );
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let assignments: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_assignments WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let occupations: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((assignments, occupations), (0, 0));
}
