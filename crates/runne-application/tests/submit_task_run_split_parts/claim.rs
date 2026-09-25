use runne_application::ports::{
    ExecutionNodeId, TaskRunClaimError, TaskRunClaimLookup, TaskRunClaimLookupResult,
    TaskRunClaimPort, TaskRunClaimReceipt, TaskRunClaimRequest, TaskRunClaimResult, TaskRunFence,
};
use runne_application::service::{ClaimTaskRunInput, ClaimTaskRunServiceError};
use runne_domain::id::IntegrityDigest;
use runne_domain::timestamp::Timestamp;

#[derive(Default)]
struct ClaimState {
    request: Option<TaskRunClaimLookup>,
    receipt: Option<TaskRunClaimReceipt>,
}

struct FakeClaimPort {
    calls: Cell<usize>,
    lookups: Cell<usize>,
    last_request: RefCell<Option<TaskRunClaimRequest>>,
    state: RefCell<ClaimState>,
    store: StrictMemStore,
}

impl TaskRunClaimPort for FakeClaimPort {
    fn lookup_task_run_claim(
        &self,
        lookup: TaskRunClaimLookup,
    ) -> Result<TaskRunClaimLookupResult, TaskRunClaimError> {
        self.lookups.set(self.lookups.get() + 1);
        let state = self.state.borrow();
        let (Some(saved), Some(receipt)) = (&state.request, &state.receipt) else {
            return Ok(TaskRunClaimLookupResult::Miss);
        };
        if saved.command_id == lookup.command_id {
            return if same_identity(saved, &lookup) {
                Ok(TaskRunClaimLookupResult::Duplicate(receipt.clone()))
            } else {
                Err(TaskRunClaimError::IdempotencyConflict)
            };
        }
        if saved.idempotency_scope == lookup.idempotency_scope
            && saved.idempotency_key == lookup.idempotency_key
        {
            return Err(TaskRunClaimError::IdempotencyConflict);
        }
        Ok(TaskRunClaimLookupResult::Miss)
    }

    fn claim_task_run(
        &self,
        request: TaskRunClaimRequest,
    ) -> Result<TaskRunClaimResult, TaskRunClaimError> {
        self.calls.set(self.calls.get() + 1);
        let receipt = TaskRunClaimReceipt {
            taskrun_id: request.taskrun_id,
            attempt_id: request.attempt_id,
            node_id: request.node_id.clone(),
            node_epoch: request.node_epoch,
            fence: TaskRunFence(41),
            lease_expires_at: Timestamp::from_unix_micros(99),
            new_version: request.expected_version + 2,
            admitted_event_id: *request.admitted_event.event_id(),
            started_event_id: *request.started_event.event_id(),
        };
        let lookup = TaskRunClaimLookup {
            command_id: request.command_id,
            idempotency_key: request.idempotency_key.clone(),
            idempotency_scope: request.idempotency_scope.clone(),
            command_fingerprint: request.command_fingerprint,
        };
        let mut inner = self.store.0.borrow_mut();
        let stream = inner.streams.entry(request.taskrun_id).or_default();
        let actual = stream.len() as u64;
        if actual != request.expected_version {
            return Err(TaskRunClaimError::StaleVersion {
                expected: request.expected_version,
                actual,
            });
        }
        stream.push(request.admitted_event.clone().into_envelope(
            actual + 1,
            Timestamp::from_unix_micros(100),
            IntegrityDigest::from_bytes([0; 32]),
        ));
        stream.push(request.started_event.clone().into_envelope(
            actual + 2,
            Timestamp::from_unix_micros(101),
            IntegrityDigest::from_bytes([0; 32]),
        ));
        *self.state.borrow_mut() = ClaimState {
            request: Some(lookup),
            receipt: Some(receipt.clone()),
        };
        *self.last_request.borrow_mut() = Some(request);
        Ok(TaskRunClaimResult::Committed(receipt))
    }
}

fn same_identity(left: &TaskRunClaimLookup, right: &TaskRunClaimLookup) -> bool {
    left.command_id == right.command_id
        && left.idempotency_key == right.idempotency_key
        && left.idempotency_scope == right.idempotency_scope
        && left.command_fingerprint == right.command_fingerprint
}

fn claim_port(store: &StrictMemStore) -> FakeClaimPort {
    FakeClaimPort {
        calls: Cell::new(0),
        lookups: Cell::new(0),
        last_request: RefCell::new(None),
        state: RefCell::new(ClaimState::default()),
        store: store.clone(),
    }
}

fn claim_input(version: u64) -> ClaimTaskRunInput {
    ClaimTaskRunInput {
        taskrun_id: TASKRUN_ID.parse().unwrap(),
        expected_version: version,
        node_id: ExecutionNodeId("linux-node-1".into()),
        node_epoch: 7,
        capability_descriptor: "linux-executor-v1".into(),
        lease_duration_ms: 30_000,
    }
}

#[test]
fn claim_sends_exact_admit_then_start_batch_once() {
    let (service, store) = make_service();
    service
        .submit_task_run(&context(1, "submit-claim"), submit_input())
        .unwrap();
    let port = claim_port(&store);
    let result = service
        .claim_task_run(&context(2, "claim-1"), claim_input(2), &port)
        .unwrap();
    assert_eq!(port.calls.get(), 1);
    let request = port.last_request.borrow();
    let request = request.as_ref().unwrap();
    assert_eq!(request.expected_version, 2);
    assert_eq!(request.node_epoch, 7);
    assert_eq!(request.lease_duration_ms, 30_000);
    assert_eq!(
        request.admitted_event.payload(),
        &TaskRunEvent::TaskRunAdmitted
    );
    assert!(
        matches!(request.started_event.payload(), TaskRunEvent::AttemptStarted { attempt_id } if *attempt_id == request.attempt_id)
    );
    assert_eq!(
        request.started_event.causation_id(),
        Some(request.admitted_event.event_id())
    );
    assert_eq!(store.stream(TASKRUN_ID.parse().unwrap()).len(), 4);
    assert!(
        matches!(result, TaskRunClaimResult::Committed(receipt) if receipt.fence == TaskRunFence(41))
    );
}

#[test]
fn stale_new_command_does_not_call_claim_port() {
    let (service, store) = make_service();
    service
        .submit_task_run(&context(1, "submit-stale"), submit_input())
        .unwrap();
    let port = claim_port(&store);
    let error = service
        .claim_task_run(&context(2, "claim-stale"), claim_input(1), &port)
        .unwrap_err();
    assert!(matches!(
        error,
        ClaimTaskRunServiceError::VersionConflict {
            expected: 1,
            actual: 2
        }
    ));
    assert_eq!(port.calls.get(), 0);
}

#[test]
fn exact_retry_replays_receipt_after_stream_is_running() {
    let (service, store) = make_service();
    service
        .submit_task_run(&context(1, "submit-duplicate-claim"), submit_input())
        .unwrap();
    let port = claim_port(&store);
    let first = service
        .claim_task_run(&context(2, "claim-duplicate"), claim_input(2), &port)
        .unwrap();
    let retry = service
        .claim_task_run(&context(2, "claim-duplicate"), claim_input(2), &port)
        .unwrap();
    let receipt = match first {
        TaskRunClaimResult::Committed(receipt) => receipt,
        _ => panic!("first claim must commit"),
    };
    assert_eq!(retry, TaskRunClaimResult::Duplicate(receipt));
    assert_eq!(port.lookups.get(), 2);
    assert_eq!(port.calls.get(), 1, "retry must not make another claim");
    let stream = store.stream(TASKRUN_ID.parse().unwrap());
    assert_eq!(stream.len(), 4);
    assert_eq!(
        TaskRun::replay(&stream).unwrap().state(),
        TaskRunState::Running
    );
}
