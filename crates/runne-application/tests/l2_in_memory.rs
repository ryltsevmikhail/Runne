//! L2-S — full TaskRun lifecycle through in-memory adapters.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use runne_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};

use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    ApplicationCommandContext, CommandCommit, CommitError, CommitResult, EventStore,
    EventStoreError, IdGenerationError, IdGenerator, IdempotencyScope, LoadedStream, PrincipalId,
    ReceiptLookup, RuntimeAuthorityId, UnitOfWork,
};
use runne_application::service::TaskRunService;
use runne_domain::command::TerminalResult;
use runne_domain::event::{Actor, EventEnvelope};
use runne_domain::id::{
    AggregateId, AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, TaskRunId,
    WorkspaceId,
};
use runne_domain::task_run::TaskRunEvent;

fn tr_id() -> TaskRunId {
    "018f2e3a-7000-7000-8000-000000000001".parse().unwrap()
}
fn conv_id() -> ConversationId {
    "018f2e3a-7000-7000-8000-000000000002".parse().unwrap()
}
fn ws_id() -> WorkspaceId {
    "018f2e3a-7000-7000-8000-000000000003".parse().unwrap()
}
#[allow(dead_code)]
fn cmd_id() -> CommandId {
    "018f2e3a-7000-7000-8000-000000000004".parse().unwrap()
}
#[allow(dead_code)]
fn idem_key() -> IdempotencyKey {
    IdempotencyKey::new("test-key").unwrap()
}
fn att_id() -> AttemptId {
    "018f2e3a-7000-7000-8000-000000000005".parse().unwrap()
}

#[allow(dead_code)]
fn ctx() -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: cmd_id(),
        idempotency_key: idem_key(),
        principal_id: PrincipalId("test".into()),
        actor: Actor::new("test").unwrap(),
    }
}

// ── In-memory shared store ────────────────────────────────────────────────

type Envelope = EventEnvelope<TaskRunEvent>;
type ReceiptMap = HashMap<(CommandId, IdempotencyKey), CommandOutcome>;

struct Inner {
    streams: HashMap<TaskRunId, Vec<Envelope>>,
    receipts: ReceiptMap,
}

#[derive(Clone)]
struct MemStore(Rc<RefCell<Inner>>);

impl MemStore {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(Inner {
            streams: HashMap::new(),
            receipts: HashMap::new(),
        })))
    }
}

impl EventStore for MemStore {
    fn load_task_run(&self, id: TaskRunId) -> Result<LoadedStream, EventStoreError> {
        let inner = self.0.borrow();
        let events = inner.streams.get(&id).cloned().unwrap_or_default();
        let cv = events.last().map(|e| e.sequence()).unwrap_or(0);
        let lei = events.last().map(|e| *e.event_id());
        Ok(LoadedStream {
            events,
            current_version: cv,
            last_event_id: lei,
        })
    }
}

impl UnitOfWork for MemStore {
    fn lookup_receipt(
        &self,
        cid: CommandId,
        ik: &IdempotencyKey,
        _s: &IdempotencyScope,
        _fp: &CommandFingerprint,
    ) -> Result<ReceiptLookup, CommitError> {
        let inner = self.0.borrow();
        match inner.receipts.get(&(cid, ik.clone())) {
            Some(outcome) => Ok(ReceiptLookup::Duplicate {
                stored_result: outcome.clone(),
            }),
            None => Ok(ReceiptLookup::Miss),
        }
    }

    fn commit(&self, payload: CommandCommit) -> Result<CommitResult, CommitError> {
        let mut inner = self.0.borrow_mut();
        let rk = (payload.command_id, payload.idempotency_key.clone());
        if let Some(outcome) = inner.receipts.get(&rk) {
            return Ok(CommitResult::Duplicate {
                stored_result: outcome.clone(),
            });
        }
        let tr_id = match payload.events.first().unwrap().correlation_id() {
            AggregateId::TaskRun(taskrun_id) => *taskrun_id,
            _ => {
                return Err(CommitError::StorageFailure(
                    runne_application::ports::StorageFailureKind::IntegrityViolation,
                ));
            }
        };
        let new_version = {
            let stream = inner.streams.entry(tr_id).or_default();
            let cv = stream.len() as u64;
            if cv != payload.expected_version {
                return Err(CommitError::VersionConflict {
                    expected: payload.expected_version,
                    actual: cv,
                });
            }
            for (seq, ue) in (cv + 1..).zip(payload.events.iter()) {
                stream.push(ue.clone().into_envelope(
                    seq,
                    runne_domain::timestamp::Timestamp::from_unix_micros(0),
                    runne_domain::id::IntegrityDigest::from_bytes([0u8; 32]),
                ));
            }
            stream.len() as u64
        };
        inner.receipts.insert(rk, payload.command_result.clone());
        Ok(CommitResult::Committed { new_version })
    }
}

impl IdGenerator for MemStore {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        Ok(tr_id())
    }

    fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError> {
        Ok(conv_id())
    }
    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        Ok(att_id())
    }
    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError> {
        Ok((1..=count as u8)
            .map(|i| {
                format!("018f2e3a-7000-7000-8000-0000000000{:02x}", i)
                    .parse()
                    .unwrap()
            })
            .collect())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

fn cmd_id_n(n: u8) -> CommandId {
    format!("018f2e3a-7000-7000-8000-0000000000{:02x}", n)
        .parse()
        .unwrap()
}
fn idem_key_n(n: u8) -> IdempotencyKey {
    IdempotencyKey::new(format!("test-key-{}", n)).unwrap()
}
fn ctx_n(n: u8) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: cmd_id_n(n),
        idempotency_key: idem_key_n(n),
        principal_id: PrincipalId("test".into()),
        actor: Actor::new("test").unwrap(),
    }
}

fn make_svc() -> TaskRunService<MemStore, MemStore, MemStore> {
    let store = MemStore::new();
    TaskRunService::new(
        store.clone(),
        store.clone(),
        store,
        RuntimeAuthorityId("test".into()),
    )
}

#[test]
fn test_full_lifecycle() {
    let svc = make_svc();
    let o = svc
        .create_task_run(
            &ctx_n(1),
            CreateTaskRunInput {
                conversation_id: conv_id(),
                workspace_id: ws_id(),
            },
        )
        .unwrap();
    let tid = match o {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        _ => panic!(),
    };
    svc.queue_task_run(
        &ctx_n(2),
        QueueTaskRunInput {
            taskrun_id: tid,
            expected_version: 1,
        },
    )
    .unwrap();
    svc.admit_task_run(
        &ctx_n(3),
        AdmitTaskRunInput {
            taskrun_id: tid,
            expected_version: 2,
        },
    )
    .unwrap();
    svc.start_attempt(
        &ctx_n(4),
        StartAttemptInput {
            taskrun_id: tid,
            expected_version: 3,
        },
    )
    .unwrap();
    svc.complete_task_run(
        &ctx_n(5),
        CompleteTaskRunInput {
            taskrun_id: tid,
            result: TerminalResult::Success,
            expected_version: 4,
        },
    )
    .unwrap();
}

#[test]
fn test_version_conflict() {
    let svc = make_svc();
    let o = svc
        .create_task_run(
            &ctx_n(10),
            CreateTaskRunInput {
                conversation_id: conv_id(),
                workspace_id: ws_id(),
            },
        )
        .unwrap();
    let tid = match o {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        _ => panic!(),
    };
    let err = svc
        .queue_task_run(
            &ctx_n(2),
            QueueTaskRunInput {
                taskrun_id: tid,
                expected_version: 99,
            },
        )
        .unwrap_err();
    assert!(matches!(
        err,
        runne_application::errors::ApplicationError::VersionConflict { .. }
    ));
}

#[test]
fn test_aggregate_not_found() {
    let svc = make_svc();
    let err = svc
        .queue_task_run(
            &ctx_n(2),
            QueueTaskRunInput {
                taskrun_id: tr_id(),
                expected_version: 1,
            },
        )
        .unwrap_err();
    assert!(matches!(
        err,
        runne_application::errors::ApplicationError::AggregateNotFound { .. }
    ));
}
