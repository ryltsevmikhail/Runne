#[tokio::test]
async fn receipt_reopen_is_read_only_and_fresh_token_allows_identical_prompt() {
    let submissions = Arc::new(AtomicUsize::new(0));
    let origin = managed_api_server(ManagedApiMock {
        submissions: submissions.clone(),
        task_run_ids: Arc::default(),
        fail_approvals: false,
        task_runs: json!([]),
        approvals: json!([]),
    })
    .await;
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("profile.sqlite3");
    let profile = [0x61; 32];
    let secure: Arc<dyn SecureStore> =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile));
    let session = mutation_test_client("receipt-authority", "receipt-lineage", 1)
        .session_info()
        .clone();
    let first_client =
        runne_runtime_client::mock_authenticated_runtime_client(&origin, session.clone()).unwrap();
    let core =
        AppCore::open_with_test_runtime_secure(&database, first_client, secure.clone(), profile)
            .unwrap();
    bind_workspace_conversation(&core, WORKSPACE);

    let first_intent = core
        .prepare_managed_task_run(PROJECT, WORKSPACE)
        .await
        .unwrap();
    let first_token = first_intent.recovery_token.clone().unwrap();
    let first_conversation = first_intent.conversation_id.clone().unwrap();
    let generation = first_intent.generation.unwrap();
    let started = core
        .start_managed_task_run(
            WORKSPACE,
            &first_conversation,
            "same prompt".into(),
            generation,
            &first_token,
        )
        .await
        .unwrap();
    assert_eq!(started.task_run_id.as_deref(), Some(TASK_RUN));
    assert_eq!(submissions.load(Ordering::SeqCst), 1);
    let same_process_recovered = core.recover_managed_task_run(&first_token).await.unwrap();
    assert_eq!(same_process_recovered.status, "accepted");
    assert_eq!(submissions.load(Ordering::SeqCst), 1);
    drop(core); // Simulates losing the client-facing acknowledgement after durable commit.

    let reopened_client =
        runne_runtime_client::mock_authenticated_runtime_client(&origin, session).unwrap();
    let reopened =
        AppCore::open_with_test_runtime_secure(&database, reopened_client, secure, profile)
            .unwrap();
    let recovered = reopened
        .recover_managed_task_run(&first_token)
        .await
        .unwrap();
    assert_eq!(recovered.status, "accepted");
    assert_eq!(recovered.task_run_id.as_deref(), Some(TASK_RUN));
    assert_eq!(recovered.stream_version, Some(2));
    assert_eq!(submissions.load(Ordering::SeqCst), 1);

    let second_intent = reopened
        .prepare_managed_task_run(PROJECT, WORKSPACE)
        .await
        .unwrap();
    let second_token = second_intent.recovery_token.clone().unwrap();
    assert_ne!(first_token, second_token);
    let first_after_second_intent = reopened
        .recover_managed_task_run(&first_token)
        .await
        .unwrap();
    assert_eq!(first_after_second_intent.status, "accepted");
    assert_eq!(
        first_after_second_intent.task_run_id.as_deref(),
        Some(TASK_RUN)
    );
    assert_eq!(submissions.load(Ordering::SeqCst), 1);
    let second = reopened
        .start_managed_task_run(
            WORKSPACE,
            second_intent.conversation_id.as_deref().unwrap(),
            "same prompt".into(),
            second_intent.generation.unwrap(),
            &second_token,
        )
        .await
        .unwrap();
    assert_eq!(second.status, "accepted");
    assert_eq!(second.task_run_id.as_deref(), Some(TASK_RUN_NEXT));
    assert_eq!(submissions.load(Ordering::SeqCst), 2);
    let second_recovered = reopened
        .recover_managed_task_run(&second_token)
        .await
        .unwrap();
    assert_eq!(second_recovered.status, "accepted");
    assert_eq!(second_recovered.task_run_id.as_deref(), Some(TASK_RUN_NEXT));
    assert_eq!(submissions.load(Ordering::SeqCst), 2);
}
