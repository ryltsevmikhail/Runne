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
        mutation_test_client("authority-a", "lineage-a", 1)
            .session_info()
            .clone(),
    )
    .expect("client");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), client)
        .expect("core");
    let conversation =
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").expect("conversation");
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").expect("workspace");
    let prompt = "Summarize the project status";
    let acknowledgement = core
        .submit_task_run(conversation, workspace, prompt.to_owned())
        .await
        .expect("reconciled submit");
    assert_eq!(acknowledgement.task_run_id().to_string(), task_run);
    assert_eq!(acknowledgement.stream_version(), 2);
    let (posted, observed) = server.await.expect("server");
    assert!(posted.starts_with("POST /v2/task-runs/submit HTTP/1.1"));
    assert!(posted.contains(&format!(r#""conversationId":"{conversation}""#)));
    assert!(posted.contains(&format!(r#""workspaceId":"{workspace}""#)));
    assert!(posted.contains(&format!(r#""prompt":"{prompt}""#)));
    let key = |request: &str| {
        request
            .lines()
            .find_map(|line| line.strip_prefix("idempotency-key: "))
            .expect("idempotency key")
            .to_owned()
    };
    assert_eq!(key(&posted), key(&observed));
    assert!(observed.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    let command_id = CanonicalId::parse(&key(&posted)).expect("command id");
    let identity = CommandIdentity::new(command_id, key(&posted)).expect("identity");
    let target = MutationTarget::try_new(
        runne_local_store::MutationOperation::TaskRunSubmit,
        runne_local_store::MutationTargetKind::Conversation,
        runne_local_store::BoundedCanonicalId::parse(conversation.to_string().as_bytes())
            .expect("target"),
    )
    .expect("target");
    let request = MutationRequest::for_conversation(
        runne_local_store::MutationOperation::TaskRunSubmit,
        target,
        0,
        CanonicalMutationCommand::SubmitTaskRun {
            conversation_id: conversation,
            workspace_id: workspace,
            prompt: Some(prompt.to_owned()),
        },
        identity,
        key(&posted),
    );
    let durable = core
        .prepare_mutation(request)
        .await
        .expect("anchored receipt");
    assert_eq!(
        durable.anchored_record.disposition(),
        runne_local_store::ClientMutationDisposition::CanonicalOutcome
    );
    assert!(matches!(
        durable.anchored_record.canonical_outcome(),
        Some(runne_local_store::CanonicalMutationOutcome::TaskRunSubmitted { new_version: 2, .. })
    ));
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
        mutation_test_client("authority-a", "lineage-a", 1)
            .session_info()
            .clone(),
    )
    .expect("client");
    let core = AppCore::open_with_test_runtime_secure(&path, client, secure.clone(), profile)
        .expect("core");
    let request = submit_request();
    let mut lease = core.prepare_mutation(request).await.expect("prepare");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatch intent");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Indeterminate { timestamp: 2 },
    )
    .expect("ambiguous result");
    drop(core);

    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        mutation_test_client("authority-a", "lineage-a", 2)
            .session_info()
            .clone(),
    )
    .expect("reconnected client");
    let reopened = AppCore::open_with_test_runtime_secure(&path, client, secure, profile)
        .expect("reopened core");
    let recovered = reopened
        .recover_anchored_mutations_v7()
        .await
        .expect("recovered lease")
        .pop()
        .expect("one lease");
    assert!(
        matches!(reopened.dispatch_prepared_mutation(recovered).await, Ok(MutationDispatchResult::TaskRunSubmitted(value)) if value.task_run_id().to_string() == task_run && value.stream_version() == 2)
    );
    let observed = server.await.expect("server");
    assert!(observed.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(observed.contains(r#""prompt":"Summarize the project status""#));
}

const LEGACY_RETRY_TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-000000000904";

#[tokio::test]
async fn retryable_legacy_submit_resends_v1_after_reopen_with_original_identity() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        let (mut submit, _) = listener.accept().await.expect("v1 submit");
        let posted = read_submit_request(&mut submit).await;
        drop(submit);
        let (mut reconcile, _) = listener.accept().await.expect("reconcile");
        let observed = read_submit_request(&mut reconcile).await;
        write_submit_reconciliation(&mut reconcile, LEGACY_RETRY_TASK_RUN_ID).await;
        (posted, observed)
    });

    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");
    let profile = [0x41; 32];
    let secure: std::sync::Arc<dyn SecureStore> = std::sync::Arc::new(
        runne_secure_store::test_support::DeterministicSecureStore::new(profile),
    );
    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        mutation_test_client("authority-a", "lineage-a", 1)
            .session_info()
            .clone(),
    )
    .expect("client");
    let core = AppCore::open_with_test_runtime_secure(&path, client, secure.clone(), profile)
        .expect("core");
    let conversation =
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").expect("conversation");
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").expect("workspace");
    let key = "018f2e3a-7000-7000-8000-000000000905".to_owned();
    let identity = CommandIdentity::new(CanonicalId::parse(&key).expect("command id"), key.clone())
        .expect("identity");
    let target = MutationTarget::try_new(
        runne_local_store::MutationOperation::TaskRunSubmit,
        runne_local_store::MutationTargetKind::Conversation,
        runne_local_store::BoundedCanonicalId::parse(conversation.to_string().as_bytes())
            .expect("target"),
    )
    .expect("target");
    let request = MutationRequest::for_conversation(
        runne_local_store::MutationOperation::TaskRunSubmit,
        target,
        0,
        CanonicalMutationCommand::SubmitTaskRun {
            conversation_id: conversation,
            workspace_id: workspace,
            prompt: None,
        },
        identity,
        key,
    );
    let mut lease = core.prepare_mutation(request).await.expect("prepare legacy submit");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatch intent");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::NotCommittedRetryable { timestamp: 2 },
    )
    .expect("not committed");
    drop(core);
    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        mutation_test_client("authority-a", "lineage-a", 2)
            .session_info()
            .clone(),
    )
    .expect("reconnected client");
    let reopened = AppCore::open_with_test_runtime_secure(&path, client, secure, profile)
        .expect("reopened core");
    let recovered = reopened
        .recover_anchored_mutations_v7()
        .await
        .expect("recovered lease")
        .pop()
        .expect("one lease");
    assert!(matches!(
        reopened.dispatch_prepared_mutation(recovered).await,
        Ok(MutationDispatchResult::TaskRunSubmitted(value))
            if value.task_run_id().to_string() == LEGACY_RETRY_TASK_RUN_ID && value.stream_version() == 2
    ));

    let (posted, observed) = server.await.expect("server");
    assert!(posted.starts_with("POST /v1/task-runs/submit HTTP/1.1"));
    assert!(posted.contains(&format!(r#""conversationId":"{conversation}""#)));
    assert!(posted.contains(&format!(r#""workspaceId":"{workspace}""#)));
    assert!(!posted.contains("prompt"));
    let idempotency_key = |request: &str| {
        request
            .lines()
            .find_map(|line| line.strip_prefix("idempotency-key: "))
            .expect("idempotency key")
            .to_owned()
    };
    assert_eq!(idempotency_key(&posted), idempotency_key(&observed));
    assert_eq!(idempotency_key(&posted), "018f2e3a-7000-7000-8000-000000000905");
    assert!(observed.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(observed.contains("submit_task_run"));
    assert!(!observed.contains("prompt"));
}
