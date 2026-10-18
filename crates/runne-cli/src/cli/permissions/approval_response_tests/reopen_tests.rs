use super::*;

#[tokio::test]
async fn linux_record_reopen_recovers_fake_lost_ack_without_prompt_or_resend() {
    let home = dirs::home_dir().expect("home directory for a private temporary state root");
    let directory = tempfile::Builder::new()
        .prefix("runne-approval-recovery-")
        .tempdir_in(home)
        .expect("private temporary state directory");
    let state_dir = directory.path().join("state");
    let events = Arc::new(Mutex::new(Vec::new()));
    let server = Arc::new(FakeApprovalServer::default());
    let intent = response_intent(runne_runtime_client::ApprovalDecisionDto::Deny);
    let mut first = FakeApprovalRuntime::with_server(approval(), events.clone(), server.clone());
    first.unknown_after_post.store(true, Ordering::Relaxed);
    let stable = StableRuntimeIdentity::from_session(&first.approval_session_info()).unwrap();
    let scope = scope_digest(&stable);
    first.durable_record_path = Some(
        state_dir
            .join("runne/cli/permission-intents")
            .join(&scope)
            .join(format!("{}.json", intent.command_id)),
    );
    let index = LinuxPermissionRecoveryIndex::new(state_dir.clone());
    let consent = MockConsent::allowed(events.clone());

    assert!(
        execute_approval_response_with_consent(&first, intent.clone(), &index, &consent)
            .await
            .is_ok()
    );
    assert_eq!(server.posts.load(Ordering::Relaxed), 1);
    assert_eq!(consent.calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &[
            "approval_get",
            "confirm",
            "approval_get",
            "consume",
            "record_durable",
            "post",
            "reconcile"
        ]
    );

    let bytes = index
        .read_existing(&scope, intent.command_id)
        .unwrap()
        .expect("durable Linux recovery file");
    assert!(bytes.len() <= MAX_RECOVERY_RECORD_BYTES);
    for disclosure in [
        first.approval.action.as_bytes(),
        first.approval.resource.as_bytes(),
        first.approval.risk_summary.as_bytes(),
    ] {
        assert!(
            !bytes
                .windows(disclosure.len())
                .any(|window| window == disclosure)
        );
    }
    let record = decode_approval_recovery_record(&bytes).unwrap();
    assert_eq!(record.command_id, intent.command_id);
    assert_eq!(record.idempotency_key, intent.idempotency_key);
    assert_eq!(record.decision, StoredApprovalDecision::Deny);
    drop(index);

    // Reopen the real filesystem index and rebuild only the fake client adapter;
    // the simulated canonical server receipt survives independently of both.
    events.lock().unwrap().clear();
    let reopened = LinuxPermissionRecoveryIndex::new(state_dir);
    let restarted = FakeApprovalRuntime::with_server(approval(), events.clone(), server.clone());
    let no_prompt = MockConsent::unavailable(events.clone());
    assert!(
        execute_approval_response_with_consent(&restarted, intent, &reopened, &no_prompt,)
            .await
            .is_ok()
    );
    assert_eq!(server.posts.load(Ordering::Relaxed), 1);
    assert_eq!(no_prompt.calls.load(Ordering::Relaxed), 0);
    assert_eq!(events.lock().unwrap().as_slice(), &["reconcile"]);
}

#[tokio::test]
async fn lost_ack_and_restart_reconcile_only_without_resending() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeApprovalRuntime::new(approval(), events.clone());
    runtime.unknown_after_post.store(true, Ordering::Relaxed);
    let index = memory_index(events.clone());
    assert!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Deny),
            &index,
            &MockConsent::allowed(events.clone()),
        )
        .await
        .is_ok()
    );
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
    events.lock().unwrap().clear();
    let restart = FakeApprovalRuntime::new(approval(), events.clone());
    assert!(matches!(
        execute_approval_response_with_consent(
            &restart,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Deny),
            &index,
            &MockConsent::unavailable(events.clone()),
        )
        .await,
        Err(CliError::PermissionCommandUnknown(_))
    ));
    assert_eq!(restart.server.posts.load(Ordering::Relaxed), 0);
    assert_eq!(events.lock().unwrap().as_slice(), &["reconcile"]);
}

#[tokio::test]
async fn wrong_task_run_ack_is_not_reported_as_success() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = FakeApprovalRuntime::new(approval(), events.clone());
    runtime.wrong_ack_task = true;
    let index = memory_index(events.clone());
    assert!(matches!(
        execute_approval_response_with_consent(
            &runtime,
            response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
            &index,
            &MockConsent::allowed(events),
        )
        .await,
        Err(CliError::PermissionCommandUnknown(_))
    ));
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
}

#[test]
fn concurrent_identical_command_ids_post_at_most_once() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = Arc::new(FakeApprovalRuntime::new(approval(), events.clone()));
    let index = Arc::new(memory_index(events.clone()));
    let barrier = Arc::new(Barrier::new(2));
    let consent = Arc::new(MockConsent {
        failure: None,
        barrier: Some(barrier),
        calls: AtomicUsize::new(0),
        events: events.clone(),
    });
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let runtime = Arc::clone(&runtime);
            let index = Arc::clone(&index);
            let consent = Arc::clone(&consent);
            scope.spawn(move || {
                let local = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                let _ = local.block_on(execute_approval_response_with_consent(
                    &*runtime,
                    response_intent(runne_runtime_client::ApprovalDecisionDto::Approve),
                    &*index,
                    &*consent,
                ));
            });
        }
    });
    assert_eq!(runtime.server.posts.load(Ordering::Relaxed), 1);
    assert_eq!(index.records.lock().unwrap().len(), 1);
}
