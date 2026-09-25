use runne_application::ports::{
    AggregateScope, EventStore, IdempotencyScope, OperationTag, PrincipalId, RuntimeAuthorityId,
    TaskRunClaimError, TaskRunClaimLookup, TaskRunClaimLookupResult, TaskRunClaimPort,
    TaskRunClaimRequest, TaskRunClaimResult,
};
use runne_application::service::ClaimTaskRunInput;
use runne_domain::event::{EventEnvelope, Sensitivity};
use runne_domain::id::{AggregateId, IntegrityDigest};
use runne_store::codec::{StoreCodec, TaskRunEventCodec};
use runne_store::integrity::compute_integrity_digest_with_global_position;
use std::sync::{Arc, Mutex};

use super::claim_failures::queued;
use super::support::*;

#[derive(Clone)]
struct CaptureClaim {
    store: runne_store::store::StoreTransaction,
    request: Arc<Mutex<Option<TaskRunClaimRequest>>>,
}

impl TaskRunClaimPort for CaptureClaim {
    fn lookup_task_run_claim(
        &self,
        lookup: TaskRunClaimLookup,
    ) -> Result<TaskRunClaimLookupResult, TaskRunClaimError> {
        self.store.lookup_task_run_claim(lookup)
    }

    fn claim_task_run(
        &self,
        request: TaskRunClaimRequest,
    ) -> Result<TaskRunClaimResult, TaskRunClaimError> {
        *self.request.lock().unwrap() = Some(request.clone());
        self.store.claim_task_run(request)
    }
}

fn committed_claim(
    database: &Database,
    tail: u8,
) -> (
    runne_application::ports::ApplicationCommandContext,
    ClaimTaskRunInput,
    TaskRunClaimRequest,
) {
    let (_, input) = queued(database, tail);
    let context = task_context(tail.wrapping_add(1), "claim-event-integrity");
    let captured = Arc::new(Mutex::new(None));
    let port = CaptureClaim {
        store: database.store.clone(),
        request: captured.clone(),
    };
    database
        .task_runs()
        .claim_task_run(&context, input.clone(), &port)
        .unwrap();
    let request = captured
        .lock()
        .unwrap()
        .clone()
        .expect("claim request captured");
    (context, input, request)
}

fn claim_lookup(
    context: &runne_application::ports::ApplicationCommandContext,
    input: &ClaimTaskRunInput,
) -> TaskRunClaimLookup {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"runne-taskrun-claim-v1");
    hasher.update(input.taskrun_id.as_bytes());
    hasher.update(input.expected_version.to_be_bytes());
    hasher.update((input.node_id.0.len() as u64).to_be_bytes());
    hasher.update(input.node_id.0.as_bytes());
    hasher.update(input.node_epoch.to_be_bytes());
    hasher.update((input.capability_descriptor.len() as u64).to_be_bytes());
    hasher.update(input.capability_descriptor.as_bytes());
    hasher.update(input.lease_duration_ms.to_be_bytes());
    TaskRunClaimLookup {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key.clone(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: RuntimeAuthorityId("project-workspace-test-authority".into()),
            principal_id: PrincipalId("owner".into()),
            operation: OperationTag::TaskRunClaim,
            aggregate_scope: AggregateScope::ExistingTaskRun {
                taskrun_id: input.taskrun_id,
            },
        },
        command_fingerprint: runne_application::fingerprint::CommandFingerprint::from_bytes(
            hasher.finalize().into(),
        ),
    }
}

fn drop_event_triggers(connection: &rusqlite::Connection) {
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='events'")
        .unwrap();
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    drop(statement);
    for name in names {
        connection
            .execute_batch(&format!("DROP TRIGGER \"{}\"", name.replace('"', "\"\"")))
            .unwrap();
    }
}

#[test]
fn exact_and_transactional_replay_reject_deleted_claim_event() {
    let database = Database::new("taskrun-claim-missing-event");
    let (context, input, request) = committed_claim(&database, 0xa7);
    let connection = database.connection();
    drop_event_triggers(&connection);
    connection
        .execute(
            "DELETE FROM events WHERE event_id=?1",
            [request.started_event.event_id().as_bytes()],
        )
        .unwrap();
    assert_eq!(
        database
            .store
            .lookup_task_run_claim(claim_lookup(&context, &input)),
        Err(TaskRunClaimError::CorruptData)
    );
    assert_eq!(
        database.store.claim_task_run(request),
        Err(TaskRunClaimError::CorruptData)
    );
}

#[test]
fn exact_and_transactional_replay_reject_claim_event_digest_drift() {
    let database = Database::new("taskrun-claim-event-drift");
    let (context, input, request) = committed_claim(&database, 0xa8);
    let connection = database.connection();
    drop_event_triggers(&connection);
    connection
        .execute(
            "UPDATE events SET integrity_digest=zeroblob(32) WHERE event_id=?1",
            [request.started_event.event_id().as_bytes()],
        )
        .unwrap();
    assert_eq!(
        database
            .store
            .lookup_task_run_claim(claim_lookup(&context, &input)),
        Err(TaskRunClaimError::CorruptData)
    );
    assert_eq!(
        database.store.claim_task_run(request),
        Err(TaskRunClaimError::CorruptData)
    );
}

#[test]
fn duplicate_replay_rejects_domain_invalid_prior_event_with_valid_digest() {
    let database = Database::new("taskrun-claim-invalid-domain-history");
    let (context, input, request) = committed_claim(&database, 0xa9);
    let connection = database.connection();
    let original = database
        .store
        .load_task_run(input.taskrun_id)
        .unwrap()
        .events[1]
        .clone();
    let payload = runne_domain::task_run::TaskRunEvent::AttemptStarted {
        attempt_id: request.attempt_id,
    };
    let payload_bytes = TaskRunEventCodec.encode(&payload).unwrap();
    let position: i64 = connection
        .query_row(
            "SELECT global_position FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=2",
            [input.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let changed = EventEnvelope::from_parts(
        *original.event_id(),
        AggregateId::TaskRun(input.taskrun_id),
        AggregateId::TaskRun(input.taskrun_id),
        original.causation_id().copied(),
        *original.command_id(),
        original.idempotency_key().clone(),
        original.schema_version(),
        original.actor().clone(),
        Sensitivity::Public,
        payload,
        original.sequence(),
        *original.timestamp(),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_with_global_position(&changed, position, &payload_bytes).unwrap();
    drop_event_triggers(&connection);
    connection
        .execute(
            "UPDATE events SET payload=?1,integrity_digest=?2 WHERE event_id=?3",
            rusqlite::params![
                payload_bytes,
                digest.as_bytes(),
                original.event_id().as_bytes()
            ],
        )
        .unwrap();

    assert_eq!(
        database
            .store
            .lookup_task_run_claim(claim_lookup(&context, &input)),
        Err(TaskRunClaimError::CorruptData)
    );
    assert_eq!(
        database.store.claim_task_run(request),
        Err(TaskRunClaimError::CorruptData)
    );
}
