fn submit_request() -> MutationRequest {
    MutationRequest::submit_task_run(
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").expect("conversation"),
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").expect("workspace"),
    )
    .expect("request")
}

async fn read_submit_request(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut bytes = [0; 8192];
    let count = stream.read(&mut bytes).await.expect("request");
    String::from_utf8(bytes[..count].to_vec()).expect("request text")
}

async fn write_submit_reconciliation(stream: &mut tokio::net::TcpStream, task_run: &str) {
    use tokio::io::AsyncWriteExt;
    let body = format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"submit_task_run","taskRunId":"{task_run}","newVersion":2}}}}"#);
    stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("reconciliation");
}

#[test]
fn submit_request_anchors_both_conversation_and_workspace_bindings() {
    let request = submit_request();
    assert_eq!(request.operation, runne_local_store::MutationOperation::TaskRunSubmit);
    assert_eq!(request.target.kind(), runne_local_store::MutationTargetKind::Conversation);
    assert_eq!(request.expected_version, 0);
    assert!(request.validate_invariants().is_ok());
    assert_eq!(request.ledger_command().expect("ledger command"), runne_local_store::NormalizedMutationCommand::SubmitTaskRun {
        conversation_id: runne_local_store::BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000901").expect("conversation"),
        workspace_id: runne_local_store::BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000902").expect("workspace"),
    });
}

#[tokio::test]
async fn duplicate_submit_identity_reuses_ledger_entry_and_changed_binding_conflicts() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .expect("core");
    let request = submit_request();
    let duplicate = request.clone();
    let first = core.prepare_mutation(request.clone()).await.expect("first prepare");
    let replay = core.prepare_mutation(duplicate).await.expect("duplicate prepare");
    assert_eq!(first.anchored_record.idempotency_key(), replay.anchored_record.idempotency_key());
    let mut changed = request;
    let CanonicalMutationCommand::SubmitTaskRun { conversation_id, .. } = changed.semantic_command else { unreachable!() };
    changed.semantic_command = CanonicalMutationCommand::SubmitTaskRun {
        conversation_id,
        workspace_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000903").expect("other workspace"),
    };
    assert!(matches!(core.prepare_mutation(changed).await, Err(AppCoreError::MutationUnavailable)));
}

#[tokio::test]
async fn lost_submit_ack_reconciles_same_authenticated_command_identity() {
    use tokio::net::TcpListener;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let task_run = "018f2e3a-7000-7000-8000-000000000904";
    let server = tokio::spawn(async move {
        let (mut submit, _) = listener.accept().await.expect("submit");
        let posted = read_submit_request(&mut submit).await;
        drop(submit);
        let (mut reconcile, _) = listener.accept().await.expect("reconcile");
        let observed = read_submit_request(&mut reconcile).await;
        write_submit_reconciliation(&mut reconcile, task_run).await;
        (posted, observed)
    });
    let directory = tempfile::tempdir().expect("directory");
    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        mutation_test_client("authority-a", "lineage-a", 1).session_info().clone(),
    ).expect("client");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), client).expect("core");
    let conversation = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").expect("conversation");
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").expect("workspace");
    let acknowledgement = core.submit_task_run(conversation, workspace).await.expect("reconciled submit");
    assert_eq!(acknowledgement.task_run_id().to_string(), task_run);
    assert_eq!(acknowledgement.stream_version(), 2);
    let (posted, observed) = server.await.expect("server");
    assert!(posted.starts_with("POST /v1/task-runs/submit HTTP/1.1"));
    assert!(posted.contains(&format!(r#""conversationId":"{conversation}""#)));
    assert!(posted.contains(&format!(r#""workspaceId":"{workspace}""#)));
    let key = |request: &str| request.lines().find_map(|line| line.strip_prefix("idempotency-key: ")).expect("idempotency key").to_owned();
    assert_eq!(key(&posted), key(&observed));
    assert!(observed.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    let command_id = CanonicalId::parse(&key(&posted)).expect("command id");
    let identity = CommandIdentity::new(command_id, key(&posted)).expect("identity");
    let target = MutationTarget::try_new(
        runne_local_store::MutationOperation::TaskRunSubmit,
        runne_local_store::MutationTargetKind::Conversation,
        runne_local_store::BoundedCanonicalId::parse(conversation.to_string().as_bytes()).expect("target"),
    ).expect("target");
    let request = MutationRequest::for_conversation(
        runne_local_store::MutationOperation::TaskRunSubmit,
        target,
        0,
        CanonicalMutationCommand::SubmitTaskRun { conversation_id: conversation, workspace_id: workspace },
        identity,
        key(&posted),
    );
    let durable = core.prepare_mutation(request).await.expect("anchored receipt");
    assert_eq!(durable.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::CanonicalOutcome);
    assert!(matches!(durable.anchored_record.canonical_outcome(), Some(runne_local_store::CanonicalMutationOutcome::TaskRunSubmitted { new_version: 2, .. })));
}

#[tokio::test]
async fn indeterminate_submit_recovers_after_reopen_without_resending_post() {
    use tokio::net::TcpListener;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let task_run = "018f2e3a-7000-7000-8000-000000000904";
    let server = tokio::spawn(async move {
        let (mut reconcile, _) = listener.accept().await.expect("reconcile after reopen");
        let observed = read_submit_request(&mut reconcile).await;
        write_submit_reconciliation(&mut reconcile, task_run).await;
        observed
    });
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");
    let profile = [0x41; 32];
    let secure: std::sync::Arc<dyn SecureStore> = std::sync::Arc::new(
        runne_secure_store::test_support::DeterministicSecureStore::new(profile),
    );
    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        mutation_test_client("authority-a", "lineage-a", 1).session_info().clone(),
    ).expect("client");
    let core = AppCore::open_with_test_runtime_secure(&path, client, secure.clone(), profile).expect("core");
    let request = submit_request();
    let mut lease = core.prepare_mutation(request).await.expect("prepare");
    core.transition_v7_under_operation(&mut lease, runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 }).expect("dispatch intent");
    core.transition_v7_under_operation(&mut lease, runne_local_store::V7MutationTransition::Indeterminate { timestamp: 2 }).expect("ambiguous result");
    drop(core);

    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        mutation_test_client("authority-a", "lineage-a", 2).session_info().clone(),
    ).expect("reconnected client");
    let reopened = AppCore::open_with_test_runtime_secure(&path, client, secure, profile).expect("reopened core");
    let recovered = reopened.recover_anchored_mutations_v7().await.expect("recovered lease").pop().expect("one lease");
    assert!(matches!(reopened.dispatch_prepared_mutation(recovered).await, Ok(MutationDispatchResult::TaskRunSubmitted(value)) if value.task_run_id().to_string() == task_run && value.stream_version() == 2));
    let observed = server.await.expect("server");
    assert!(observed.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}
