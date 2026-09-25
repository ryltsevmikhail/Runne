struct StaleMissPort<'a> {
    first_lookup: Cell<bool>,
    delegate: &'a FakeClaimPort,
}

impl TaskRunClaimPort for StaleMissPort<'_> {
    fn lookup_task_run_claim(
        &self,
        lookup: TaskRunClaimLookup,
    ) -> Result<TaskRunClaimLookupResult, TaskRunClaimError> {
        if self.first_lookup.replace(false) {
            Ok(TaskRunClaimLookupResult::Miss)
        } else {
            self.delegate.lookup_task_run_claim(lookup)
        }
    }

    fn claim_task_run(
        &self,
        request: TaskRunClaimRequest,
    ) -> Result<TaskRunClaimResult, TaskRunClaimError> {
        self.delegate.claim_task_run(request)
    }
}

#[test]
fn stale_initial_miss_replays_if_first_claim_commits_before_stream_preflight() {
    let (service, store) = make_service();
    service
        .submit_task_run(&context(1, "submit-claim-race"), submit_input())
        .unwrap();
    let delegate = claim_port(&store);
    let first = service
        .claim_task_run(&context(2, "claim-race"), claim_input(2), &delegate)
        .unwrap();
    let committed = match first {
        TaskRunClaimResult::Committed(receipt) => receipt,
        _ => panic!("first claim must commit"),
    };

    // Models a concurrent caller whose earlier read observed Miss, while the
    // first claim commits before this caller loads the now-Running stream.
    let racing = StaleMissPort {
        first_lookup: Cell::new(true),
        delegate: &delegate,
    };
    assert_eq!(
        service
            .claim_task_run(&context(2, "claim-race"), claim_input(2), &racing)
            .unwrap(),
        TaskRunClaimResult::Duplicate(committed)
    );
    assert_eq!(delegate.calls.get(), 1);
}

#[test]
fn changed_node_or_key_conflicts_before_stream_preflight() {
    let (service, store) = make_service();
    service
        .submit_task_run(&context(1, "submit-claim-conflict"), submit_input())
        .unwrap();
    let port = claim_port(&store);
    service
        .claim_task_run(&context(2, "claim-conflict"), claim_input(2), &port)
        .unwrap();

    let mut changed_node = claim_input(2);
    changed_node.node_id = ExecutionNodeId("other-node".into());
    let node_error = service
        .claim_task_run(&context(2, "claim-conflict"), changed_node, &port)
        .unwrap_err();
    assert_eq!(
        node_error,
        ClaimTaskRunServiceError::Port(TaskRunClaimError::IdempotencyConflict)
    );
    let key_error = service
        .claim_task_run(&context(2, "different-key"), claim_input(2), &port)
        .unwrap_err();
    assert_eq!(
        key_error,
        ClaimTaskRunServiceError::Port(TaskRunClaimError::IdempotencyConflict)
    );
    assert_eq!(port.calls.get(), 1);
}

struct FailingClaimPort;
impl TaskRunClaimPort for FailingClaimPort {
    fn lookup_task_run_claim(
        &self,
        _: TaskRunClaimLookup,
    ) -> Result<TaskRunClaimLookupResult, TaskRunClaimError> {
        Ok(TaskRunClaimLookupResult::Miss)
    }

    fn claim_task_run(
        &self,
        _: TaskRunClaimRequest,
    ) -> Result<TaskRunClaimResult, TaskRunClaimError> {
        Err(TaskRunClaimError::Unavailable)
    }
}

#[test]
fn claim_store_errors_are_returned_fail_closed() {
    let (service, _) = make_service();
    service
        .submit_task_run(&context(1, "submit-claim-error"), submit_input())
        .unwrap();
    let error = service
        .claim_task_run(
            &context(2, "claim-error"),
            claim_input(2),
            &FailingClaimPort,
        )
        .unwrap_err();
    assert_eq!(
        error,
        ClaimTaskRunServiceError::Port(TaskRunClaimError::Unavailable)
    );
}

#[test]
fn non_queued_state_does_not_call_claim_port() {
    let (service, store) = make_service();
    service
        .submit_task_run(&context(1, "submit-running"), submit_input())
        .unwrap();
    service
        .admit_task_run(
            &context(2, "admit-running"),
            runne_application::commands::AdmitTaskRunInput {
                taskrun_id: TASKRUN_ID.parse().unwrap(),
                expected_version: 2,
            },
        )
        .unwrap();
    let port = claim_port(&store);
    let error = service
        .claim_task_run(&context(3, "claim-running"), claim_input(3), &port)
        .unwrap_err();
    assert_eq!(error, ClaimTaskRunServiceError::NotQueued);
    assert_eq!(port.calls.get(), 0);
}
