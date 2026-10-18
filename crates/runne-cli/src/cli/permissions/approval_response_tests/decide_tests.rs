use super::*;

#[tokio::test]
async fn approve_and_deny_confirm_exact_review_then_durable_record_precedes_single_post() {
    for decision in [
        runne_runtime_client::ApprovalDecisionDto::Approve,
        runne_runtime_client::ApprovalDecisionDto::Deny,
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let runtime = FakeApprovalRuntime::new(approval(), events.clone());
        let index = memory_index(events.clone());
        let consent = MockConsent::allowed(events.clone());
        assert!(
            execute_approval_response_with_consent(
                &runtime,
                response_intent(decision),
                &index,
                &consent,
            )
            .await
            .is_ok()
        );
        assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
        assert_eq!(index.records.lock().unwrap().len(), 1);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                "approval_get",
                "confirm",
                "approval_get",
                "consume",
                "record_durable",
                "post"
            ]
        );
    }
}

#[tokio::test]
async fn cancel_unavailable_expiry_and_changed_tuple_never_create_or_post() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeApprovalRuntime::new(approval(), events.clone());
    let index = memory_index(events.clone());
    let consent = MockConsent {
        failure: Some(ApprovalConfirmationError::Declined),
        barrier: None,
        calls: AtomicUsize::new(0),
        events: events.clone(),
    };
    assert!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &consent,
        )
        .await
        .is_err()
    );
    assert!(index.records.lock().unwrap().is_empty());
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);

    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeApprovalRuntime::new(approval(), events.clone());
    let index = memory_index(events.clone());
    assert!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &MockConsent::unavailable(events.clone()),
        )
        .await
        .is_err()
    );
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut expired = approval();
    expired.expires_at = 1;
    let runtime = FakeApprovalRuntime::new(expired, events.clone());
    let index = memory_index(events.clone());
    let consent = MockConsent::allowed(events.clone());
    assert!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &consent,
        )
        .await
        .is_err()
    );
    assert_eq!(consent.calls.load(Ordering::Relaxed), 0);
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = FakeApprovalRuntime::new(approval(), events.clone());
    runtime.changed_tuple_on_refetch = true;
    let index = memory_index(events.clone());
    let consent = MockConsent::allowed(events.clone());
    assert!(matches!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &consent,
        )
        .await,
        Err(CliError::PermissionRecoveryConflict(_))
    ));
    assert!(index.records.lock().unwrap().is_empty());
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn session_change_and_cross_kind_or_corrupt_records_stop_before_post() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = FakeApprovalRuntime::new(approval(), events.clone());
    runtime.changed_session_after_first = true;
    let index = memory_index(events.clone());
    let consent = MockConsent::allowed(events.clone());
    assert!(matches!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &consent,
        )
        .await,
        Err(CliError::PermissionRecoveryConflict(_))
    ));
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);

    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeApprovalRuntime::new(approval(), events.clone());
    let index = memory_index(events.clone());
    let mode_bytes = saved_record(&crate::permissions_tests::intent());
    index
        .records
        .lock()
        .unwrap()
        .push(("other-scope".to_owned(), COMMAND.to_owned(), mode_bytes));
    assert!(matches!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &MockConsent::allowed(events.clone()),
        )
        .await,
        Err(CliError::PermissionRecoveryConflict(_))
    ));
    assert_eq!(runtime.approval_reads.load(Ordering::Relaxed), 0);
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);

    index.records.lock().unwrap().clear();
    index.records.lock().unwrap().push((
        "other-scope".to_owned(),
        COMMAND.to_owned(),
        b"{".to_vec(),
    ));
    assert!(matches!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &MockConsent::allowed(events.clone()),
        )
        .await,
        Err(CliError::PermissionRecoveryCorrupt(_))
    ));
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 0);
}
