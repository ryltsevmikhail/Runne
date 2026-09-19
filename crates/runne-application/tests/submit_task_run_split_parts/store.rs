use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use runne_application::commands::{CommandOutcome, SubmitTaskRunInput};
use runne_application::errors::ApplicationError;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    ApplicationCommandContext, CommandCommit, CommitError, CommitResult, EventStore,
    EventStoreError, IdGenerationError, IdGenerator, IdempotencyScope, LoadedStream, PrincipalId,
    ReceiptLookup, RuntimeAuthorityId, StorageFailureKind, UnitOfWork,
};
use runne_application::service::TaskRunService;
use runne_domain::event::{Actor, EventEnvelope};
use runne_domain::id::{
    AggregateId, AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, TaskRunId,
    WorkspaceId,
};
use runne_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};

type Envelope = EventEnvelope<TaskRunEvent>;

const TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
/// The next id the serial generator yields after the failed first attempt.
const RETRY_TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
const OTHER_WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-0000000000aa";
const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000003";

/// Stored durable receipt: identity plus outcome.
struct StoredReceipt {
    idempotency_key: IdempotencyKey,
    scope: IdempotencyScope,
    fingerprint: CommandFingerprint,
    outcome: CommandOutcome,
}

struct Inner {
    streams: HashMap<TaskRunId, Vec<Envelope>>,
    receipts: HashMap<CommandId, StoredReceipt>,
}

/// In-memory unit-of-work mirroring the durable identity rules of the SQLite
/// store: exact replay (command ID, key, scope, fingerprint) returns the
/// stored acknowledgement; a changed identity field — a different payload
/// under the same command ID, or a regenerated command ID under the same
/// scope and key — is an idempotency conflict.
#[derive(Clone)]
struct StrictMemStore(
    Rc<RefCell<Inner>>,
    Rc<Cell<usize>>,
    Rc<Cell<bool>>,
    Rc<Cell<u64>>,
    Rc<Cell<u64>>,
);

impl StrictMemStore {
    fn new() -> Self {
        Self(
            Rc::new(RefCell::new(Inner {
                streams: HashMap::new(),
                receipts: HashMap::new(),
            })),
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(false)),
            Rc::new(Cell::new(1)),
            Rc::new(Cell::new(1)),
        )
    }

    /// Makes the next `commit` fail before any stream mutation.
    fn fail_next_commit(&self) {
        self.2.set(true);
    }

    fn commits(&self) -> usize {
        self.1.get()
    }

    fn stream(&self, id: TaskRunId) -> Vec<Envelope> {
        self.0.borrow().streams.get(&id).cloned().unwrap_or_default()
    }

    fn conflict(stored_command_id: CommandId, attempted: CommandId, stored: CommandFingerprint, fingerprint: CommandFingerprint) -> CommitError {
        CommitError::IdempotencyConflict {
            stored_command_id,
            attempted_command_id: attempted,
            stored_fingerprint: stored,
            attempted_fingerprint: fingerprint,
        }
    }

    /// Exact replay by command ID first; then a (scope, key) collision with a
    /// regenerated command ID — both fail closed like the SQLite store.
    fn check_duplicate(
        inner: &Inner,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<ReceiptLookup, CommitError> {
        if let Some(stored) = inner.receipts.get(&command_id) {
            if stored.idempotency_key == *idempotency_key
                && stored.scope == *scope
                && stored.fingerprint == *fingerprint
            {
                return Ok(ReceiptLookup::Duplicate {
                    stored_result: stored.outcome.clone(),
                });
            }
            return Err(Self::conflict(
                command_id,
                command_id,
                stored.fingerprint,
                *fingerprint,
            ));
        }
        if let Some((stored_command_id, stored)) = inner
            .receipts
            .iter()
            .find(|(_, stored)| stored.scope == *scope && stored.idempotency_key == *idempotency_key)
        {
            return Err(Self::conflict(
                *stored_command_id,
                command_id,
                stored.fingerprint,
                *fingerprint,
            ));
        }
        Ok(ReceiptLookup::Miss)
    }

    fn target_stream_id(payload: &CommandCommit) -> Result<TaskRunId, CommitError> {
        match payload.events.first().map(|event| event.correlation_id()) {
            Some(AggregateId::TaskRun(taskrun_id)) => Ok(*taskrun_id),
            _ => Err(CommitError::StorageFailure(StorageFailureKind::IntegrityViolation)),
        }
    }
}

impl EventStore for StrictMemStore {
    fn load_task_run(&self, id: TaskRunId) -> Result<LoadedStream, EventStoreError> {
        let inner = self.0.borrow();
        let events = inner.streams.get(&id).cloned().unwrap_or_default();
        Ok(LoadedStream {
            current_version: events.last().map(|e| e.sequence()).unwrap_or(0),
            last_event_id: events.last().map(|e| *e.event_id()),
            events,
        })
    }
}

impl UnitOfWork for StrictMemStore {
    fn lookup_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<ReceiptLookup, CommitError> {
        let inner = self.0.borrow();
        Self::check_duplicate(&inner, command_id, idempotency_key, scope, fingerprint)
    }

    fn commit(&self, payload: CommandCommit) -> Result<CommitResult, CommitError> {
        self.1.set(self.1.get() + 1);
        if self.2.replace(false) {
            return Err(CommitError::StorageFailure(StorageFailureKind::Unavailable));
        }
        let mut inner = self.0.borrow_mut();
        if let ReceiptLookup::Duplicate { stored_result } = Self::check_duplicate(
            &inner,
            payload.command_id,
            &payload.idempotency_key,
            &payload.idempotency_scope,
            &payload.command_fingerprint,
        )? {
            return Ok(CommitResult::Duplicate { stored_result });
        }
        let taskrun_id = Self::target_stream_id(&payload)?;
        let stream = inner.streams.entry(taskrun_id).or_default();
        let current = stream.len() as u64;
        if current != payload.expected_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_version,
                actual: current,
            });
        }
        for (sequence, event) in (current + 1..).zip(payload.events.iter()) {
            stream.push(event.clone().into_envelope(
                sequence,
                runne_domain::timestamp::Timestamp::from_unix_micros(0),
                runne_domain::id::IntegrityDigest::from_bytes([0; 32]),
            ));
        }
        let new_version = stream.len() as u64;
        inner.receipts.insert(
            payload.command_id,
            StoredReceipt {
                idempotency_key: payload.idempotency_key,
                scope: payload.idempotency_scope,
                fingerprint: payload.command_fingerprint,
                outcome: payload.command_result,
            },
        );
        Ok(CommitResult::Committed { new_version })
    }
}

impl IdGenerator for StrictMemStore {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        let serial = self.3.get();
        self.3.set(serial + 1);
        Ok(format!("{TASKRUN_ID_HEAD}{serial:02x}").parse().unwrap())
    }

    fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError> {
        Ok(CONVERSATION_ID.parse().unwrap())
    }

    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        Ok(ATTEMPT_ID.parse().unwrap())
    }

    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError> {
        let base = self.4.replace(self.4.get() + count as u64);
        Ok((0..count as u64)
            .map(|offset| {
                format!("{EVENT_ID_HEAD}{:012x}", base + offset)
                    .parse()
                    .unwrap()
            })
            .collect())
    }
}

const TASKRUN_ID_HEAD: &str = "018f2e3a-7000-7000-8000-0000000000";
const EVENT_ID_HEAD: &str = "018f2e3a-7000-7000-8000-";
