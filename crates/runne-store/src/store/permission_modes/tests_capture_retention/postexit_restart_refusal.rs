//! Same TaskRun public restart refusal; AttemptId is not InvocationId.
use super::metadata::Area;
use crate::store::StoreTransaction;
use runne_application::{
    commands::StartAttemptInput,
    errors::ApplicationError,
    ports::{
        ApplicationCommandContext, IdGenerationError, IdGenerator, PrincipalId, RuntimeAuthorityId,
    },
    service::TaskRunService,
};
use runne_domain::{
    error::DomainError,
    event::Actor,
    id::{
        AttemptId, CheckpointId, CommandId, ConversationId, CycleId, EventId, IdempotencyKey,
        MessageId, TaskRunId,
    },
    task_run::TaskRunState,
};
use std::sync::{Arc, Mutex};

pub(super) fn assert_refused(store: &StoreTransaction, saved: &Area, version: u64) {
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let ids = RecordingIds {
        store: store.clone(),
        attempts: attempts.clone(),
    };
    let service = TaskRunService::new(
        store.clone(),
        store.clone(),
        ids,
        RuntimeAuthorityId(hex::encode(saved.authority)),
    );
    let context = ApplicationCommandContext {
        command_id: CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes()),
        idempotency_key: IdempotencyKey::new("postexit-fresh-start-refusal").unwrap(),
        principal_id: PrincipalId(saved.principal.clone()),
        actor: Actor::new("postexit-recovery-test").unwrap(),
    };
    assert_no_receipt(store, &context);
    let result = service.start_attempt(
        &context,
        StartAttemptInput {
            taskrun_id: saved.identity().taskrun_id,
            expected_version: version,
        },
    );
    assert!(
        matches!(
            result,
            Err(ApplicationError::Domain(DomainError::TerminalImmutable {
                current: TaskRunState::Unrecoverable,
            }))
        ),
        "expected terminal-state refusal, got {result:?}"
    );
    let generated = attempts.lock().unwrap();
    assert_eq!(generated.len(), 1);
    assert_ne!(generated[0], saved.identity().attempt_id);
    runne_domain::id::validate_uuid_v7_bytes(generated[0].as_bytes()).unwrap();
    assert_no_receipt(store, &context);
    // The caller checks exact stream/event IDs, capture, spent, attempt and
    // terminal/stop/occupation rows, trust, marker and original-area cleanup.
}

fn assert_no_receipt(store: &StoreTransaction, context: &ApplicationCommandContext) {
    let reader = store.inner.reader.lock().unwrap();
    let count: i64 = reader
        .query_row(
            "SELECT count(*) FROM command_receipts WHERE command_id=?1 OR idempotency_key=?2",
            rusqlite::params![
                context.command_id.as_bytes().as_slice(),
                context.idempotency_key.as_str().as_bytes()
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 0,
        "fresh refused command must not be receipt replay or commit"
    );
}

struct RecordingIds {
    store: StoreTransaction,
    attempts: Arc<Mutex<Vec<AttemptId>>>,
}
impl IdGenerator for RecordingIds {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        self.store.next_taskrun_id()
    }
    fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError> {
        self.store.next_conversation_id()
    }
    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        let id = self.store.next_attempt_id()?;
        self.attempts.lock().unwrap().push(id);
        Ok(id)
    }
    fn next_message_id(&self) -> Result<MessageId, IdGenerationError> {
        self.store.next_message_id()
    }
    fn next_cycle_id(&self) -> Result<CycleId, IdGenerationError> {
        self.store.next_cycle_id()
    }
    fn next_checkpoint_id(&self) -> Result<CheckpointId, IdGenerationError> {
        self.store.next_checkpoint_id()
    }
    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError> {
        self.store.next_event_ids(count)
    }
}
