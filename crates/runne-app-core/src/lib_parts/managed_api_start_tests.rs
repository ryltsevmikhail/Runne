#[tokio::test]
async fn managed_public_prepare_start_and_duplicate_return_one_canonical_task_run() {
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
    let profile = [0x52; 32];
    let secure: Arc<dyn SecureStore> =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile));
    let session = mutation_test_client("managed-authority", "managed-lineage", 1)
        .session_info()
        .clone();
    let client = runne_runtime_client::mock_authenticated_runtime_client(&origin, session).unwrap();
    let core = AppCore::open_with_test_runtime_secure(
        &directory.path().join("profile.sqlite3"),
        client,
        secure,
        profile,
    )
    .unwrap();
    bind_workspace_conversation(&core, WORKSPACE);
    let prepared = core
        .prepare_managed_task_run(PROJECT, WORKSPACE)
        .await
        .unwrap();
    assert!(prepared.can_start, "preflight: {prepared:?}");
    let conversation = prepared.conversation_id.clone().unwrap();
    assert!(CanonicalId::parse(&conversation).is_ok());
    assert_eq!(prepared.authority.provider.status, "unavailable");
    assert_eq!(prepared.authority.model.status, "unavailable");
    assert_eq!(prepared.authority.policy.status, "unavailable");
    assert_eq!(
        prepared.draft_policy,
        ManagedTaskDraftPolicy::ProtectedRestart
    );
    let token = prepared
        .recovery_token
        .clone()
        .unwrap_or_else(|| panic!("preflight: {prepared:?}"));
    let generation = prepared.generation.unwrap();
    let (first, second) = tokio::join!(
        core.start_managed_task_run(
            WORKSPACE,
            &conversation,
            "Run a bounded task".into(),
            generation,
            &token
        ),
        core.start_managed_task_run(
            WORKSPACE,
            &conversation,
            "Run a bounded task".into(),
            generation,
            &token
        ),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    let repeated = core
        .start_managed_task_run(
            WORKSPACE,
            &conversation,
            "Run a bounded task".into(),
            generation,
            &token,
        )
        .await
        .unwrap();
    assert_eq!(first.status, "accepted");
    assert_eq!(first.task_run_id.as_deref(), Some(TASK_RUN));
    assert_eq!(second.task_run_id, first.task_run_id);
    assert_eq!(repeated.task_run_id, first.task_run_id);
    assert_eq!(submissions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn managed_start_rejects_wrong_scope_and_stale_generation_before_submit() {
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
    let profile = [0x53; 32];
    let secure: Arc<dyn SecureStore> =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile));
    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        mutation_test_client("managed-authority", "managed-lineage", 1)
            .session_info()
            .clone(),
    )
    .unwrap();
    let core = AppCore::open_with_test_runtime_secure(
        &directory.path().join("profile.sqlite3"),
        client,
        secure,
        profile,
    )
    .unwrap();
    bind_workspace_conversation(&core, WORKSPACE);
    let prepared = core
        .prepare_managed_task_run(PROJECT, WORKSPACE)
        .await
        .unwrap();
    let token = prepared
        .recovery_token
        .clone()
        .unwrap_or_else(|| panic!("preflight: {prepared:?}"));
    let conversation = prepared.conversation_id.unwrap();
    assert!(
        core.start_managed_task_run(
            "018f2e3a-7000-7000-8000-000000000920",
            &conversation,
            "task".into(),
            prepared.generation.unwrap(),
            &token
        )
        .await
        .is_err()
    );
    assert!(
        core.start_managed_task_run(
            WORKSPACE,
            &conversation,
            "task".into(),
            prepared.generation.unwrap() + 1,
            &token
        )
        .await
        .is_err()
    );
    assert!(
        core.start_managed_task_run(
            WORKSPACE,
            "018f2e3a-7000-7000-8000-000000000920",
            "task".into(),
            prepared.generation.unwrap(),
            &token
        )
        .await
        .is_err()
    );
    assert_eq!(submissions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn managed_preflight_with_missing_submit_capability_stays_unavailable() {
    let submissions = Arc::new(AtomicUsize::new(0));
    let origin = managed_api_server(ManagedApiMock {
        submissions: submissions.clone(),
        task_run_ids: Arc::default(),
        fail_approvals: false,
        task_runs: json!([]),
        approvals: json!([]),
    })
    .await;
    let mut session = mutation_test_client("managed-authority", "managed-lineage", 1)
        .session_info()
        .clone();
    session
        .capabilities
        .retain(|value| value != "task_run.submit.v2");
    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/local-runtime/capability-digest/v1\0");
    digest.update(
        u32::try_from(session.capabilities.len())
            .unwrap()
            .to_be_bytes(),
    );
    for capability in &session.capabilities {
        digest.update(u32::try_from(capability.len()).unwrap().to_be_bytes());
        digest.update(capability.as_bytes());
    }
    session.capability_digest = hex::encode(digest.finalize());
    let client = runne_runtime_client::mock_authenticated_runtime_client(&origin, session).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let core =
        AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), client).unwrap();
    let preflight = core
        .prepare_managed_task_run(PROJECT, WORKSPACE)
        .await
        .unwrap();
    assert!(!preflight.can_start);
    assert_eq!(
        preflight.start_unavailable_reason,
        Some("submit_capability_missing")
    );
    assert_eq!(
        preflight.draft_policy,
        ManagedTaskDraftPolicy::ProtectedRestart
    );
    assert!(preflight.recovery_token.is_none());
    assert_eq!(submissions.load(Ordering::SeqCst), 0);
}

async fn managed_revocation_fixture(profile: u8) -> (tempfile::TempDir, AppCore, Arc<AtomicUsize>) {
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
    let profile = [profile; 32];
    let secure: Arc<dyn SecureStore> =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile));
    let session = mutation_test_client("managed-authority", "managed-lineage", 1)
        .session_info()
        .clone();
    let client = runne_runtime_client::mock_authenticated_runtime_client(&origin, session).unwrap();
    let core = AppCore::open_with_test_runtime_secure(
        &directory.path().join("profile.sqlite3"),
        client,
        secure,
        profile,
    )
    .unwrap();
    bind_workspace_conversation(&core, WORKSPACE);
    (directory, core, submissions)
}

#[tokio::test]
async fn managed_preflight_after_runtime_revocation_has_no_recovery_token() {
    let (_directory, core, submissions) = managed_revocation_fixture(0x54).await;
    core.set_runtime_availability(RuntimeAvailability::Revoked)
        .unwrap();

    let prepared = core.prepare_managed_task_run(PROJECT, WORKSPACE).await;
    assert!(matches!(prepared, Err(AppCoreError::RuntimeUnavailable)));
    assert_eq!(submissions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn managed_start_after_runtime_revocation_does_not_submit() {
    let (_directory, core, submissions) = managed_revocation_fixture(0x55).await;
    let prepared = core
        .prepare_managed_task_run(PROJECT, WORKSPACE)
        .await
        .unwrap();
    assert!(prepared.can_start, "preflight: {prepared:?}");
    let token = prepared.recovery_token.unwrap();
    let conversation = prepared.conversation_id.unwrap();
    let generation = prepared.generation.unwrap();
    core.set_runtime_availability(RuntimeAvailability::Revoked)
        .unwrap();

    assert!(matches!(
        core.start_managed_task_run(WORKSPACE, &conversation, "task".into(), generation, &token)
            .await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    assert_eq!(submissions.load(Ordering::SeqCst), 0);
}

#[cfg(target_os = "linux")]
include!("managed_task_draft_tests.rs");
