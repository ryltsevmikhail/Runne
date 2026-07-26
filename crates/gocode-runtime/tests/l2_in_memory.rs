#![allow(clippy::needless_borrows_for_generic_args)]

use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};
use std::time::Duration;

use gocode_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use gocode_application::fingerprint::CommandFingerprint;
use gocode_application::ports::{
    ApplicationCommandContext, CommandCommit, CommitError, CommitResult, EventStore,
    EventStoreError, IdGenerationError, IdGenerator, IdempotencyScope, LoadedStream, PrincipalId,
    ReceiptLookup, RuntimeAuthorityId, UnitOfWork,
};
use gocode_application::service::TaskRunService;
use gocode_domain::event::{Actor, EventEnvelope};
use gocode_domain::id::{
    AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId,
    WorkspaceId,
};
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;
use gocode_runtime::Runtime;
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{ShutdownMode, ShutdownOutcome};

struct State {
    streams: HashMap<TaskRunId, Vec<EventEnvelope<TaskRunEvent>>>,
    receipts: HashMap<(CommandId, IdempotencyKey), CommandOutcome>,
}
#[derive(Clone)]
struct InMemoryStore(Arc<Mutex<State>>);
impl InMemoryStore {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            streams: HashMap::new(),
            receipts: HashMap::new(),
        })))
    }
}
impl EventStore for InMemoryStore {
    fn load_task_run(&self, id: TaskRunId) -> Result<LoadedStream, EventStoreError> {
        let s = self.0.lock().unwrap();
        let events = s.streams.get(&id).cloned().unwrap_or_default();
        let cv = events.last().map(|e| e.sequence()).unwrap_or(0);
        let lei = events.last().map(|e| *e.event_id());
        Ok(LoadedStream {
            events,
            current_version: cv,
            last_event_id: lei,
        })
    }
}
impl UnitOfWork for InMemoryStore {
    fn lookup_receipt(
        &self,
        cid: CommandId,
        ik: &IdempotencyKey,
        _s: &IdempotencyScope,
        _fp: &CommandFingerprint,
    ) -> Result<ReceiptLookup, CommitError> {
        let s = self.0.lock().unwrap();
        match s.receipts.get(&(cid, ik.clone())) {
            Some(o) => Ok(ReceiptLookup::Duplicate {
                stored_result: o.clone(),
            }),
            None => Ok(ReceiptLookup::Miss),
        }
    }
    fn commit(&self, payload: CommandCommit) -> Result<CommitResult, CommitError> {
        let mut s = self.0.lock().unwrap();
        let rk = (payload.command_id, payload.idempotency_key.clone());
        if let Some(outcome) = s.receipts.get(&rk) {
            return Ok(CommitResult::Duplicate {
                stored_result: outcome.clone(),
            });
        }
        let tr_id = *payload.events.first().unwrap().taskrun_id();
        let new_version = {
            let stream = s.streams.entry(tr_id).or_default();
            let cv = stream.len() as u64;
            if cv != payload.expected_version {
                return Err(CommitError::VersionConflict {
                    expected: payload.expected_version,
                    actual: cv,
                });
            }
            for (i, ue) in payload.events.iter().enumerate() {
                stream.push(ue.clone().into_envelope(
                    cv + 1 + i as u64,
                    Timestamp::from_unix_micros(0),
                    IntegrityDigest::from_bytes([0u8; 32]),
                ));
            }
            stream.len() as u64
        };
        s.receipts.insert(rk, payload.command_result.clone());
        Ok(CommitResult::Committed { new_version })
    }
}
impl IdGenerator for InMemoryStore {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        Ok("018f2e3a-7000-7000-8000-000000000001".parse().unwrap())
    }
    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        Ok("018f2e3a-7000-7000-8000-000000000005".parse().unwrap())
    }
    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError> {
        static NEXT: AtomicU8 = AtomicU8::new(10);
        Ok((0..count)
            .map(|_| {
                format!(
                    "018f2e3a-7000-7000-8000-0000000000{:02x}",
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )
                .parse()
                .unwrap()
            })
            .collect())
    }
}

type TestService = TaskRunService<InMemoryStore, InMemoryStore, InMemoryStore>;
fn make_service() -> (Arc<TestService>, RuntimeAuthorityId) {
    let s = InMemoryStore::new();
    let a = RuntimeAuthorityId("test".into());
    (
        Arc::new(TaskRunService::new(
            s.clone(),
            s.clone(),
            s.clone(),
            a.clone(),
        )),
        a,
    )
}
fn cfg() -> RuntimeConfig {
    RuntimeConfig::default()
}
fn ctx(n: u8) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000000{:02x}", n)
            .parse()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("key-{}", n)).unwrap(),
        principal_id: PrincipalId("t".into()),
        actor: Actor::new("t").unwrap(),
    }
}
fn cid() -> ConversationId {
    "018f2e3a-7000-7000-8000-00000000000a".parse().unwrap()
}
fn wid() -> WorkspaceId {
    "018f2e3a-7000-7000-8000-00000000000b".parse().unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn test_full_lifecycle() {
    let (svc, _) = make_service();
    let (h, mut c) = Runtime::start_borrowed(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
        svc,
        cfg(),
    )
    .unwrap();
    let o = h
        .create_task_run(
            ctx(1),
            CreateTaskRunInput {
                conversation_id: cid(),
                workspace_id: wid(),
            },
        )
        .await
        .unwrap();
    let t = match o {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        _ => panic!(),
    };
    h.queue_task_run(
        ctx(2),
        QueueTaskRunInput {
            taskrun_id: t,
            expected_version: 1,
        },
    )
    .await
    .unwrap();
    h.admit_task_run(
        ctx(3),
        AdmitTaskRunInput {
            taskrun_id: t,
            expected_version: 2,
        },
    )
    .await
    .unwrap();
    h.start_attempt(
        ctx(4),
        StartAttemptInput {
            taskrun_id: t,
            expected_version: 3,
        },
    )
    .await
    .unwrap();
    h.complete_task_run(
        ctx(5),
        CompleteTaskRunInput {
            taskrun_id: t,
            result: gocode_domain::command::TerminalResult::Success,
            expected_version: 4,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        c.shutdown(ShutdownMode::Graceful {
            timeout: Duration::from_secs(5)
        })
        .await,
        ShutdownOutcome::Quiesced
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn test_graceful_shutdown_completes_accepted() {
    let (svc, _) = make_service();
    let (h, mut c) = Runtime::start_borrowed(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
        svc,
        cfg(),
    )
    .unwrap();
    let o = h
        .create_task_run(
            ctx(10),
            CreateTaskRunInput {
                conversation_id: cid(),
                workspace_id: wid(),
            },
        )
        .await
        .unwrap();
    let t = match o {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        _ => panic!(),
    };
    let h2 = h.clone();
    let j = tokio::spawn(async move {
        h2.queue_task_run(
            ctx(11),
            QueueTaskRunInput {
                taskrun_id: t,
                expected_version: 1,
            },
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(matches!(
        c.shutdown(ShutdownMode::Graceful {
            timeout: Duration::from_secs(5)
        })
        .await,
        ShutdownOutcome::Quiesced
    ));
    assert!(j.await.unwrap().is_ok());
}
