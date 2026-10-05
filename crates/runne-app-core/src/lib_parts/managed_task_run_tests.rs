#[tokio::test]
async fn managed_recovery_reconciles_nonterminal_token_without_submit_dispatch() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 8192];
        let used = stream.read(&mut bytes).await.unwrap();
        let request = String::from_utf8_lossy(&bytes[..used]).into_owned();
        let body = r#"{"disposition":"durably_recorded","outcome":{"operation":"submit_task_run","taskRunId":"018f2e3a-7000-7000-8000-000000000904","newVersion":2}}"#;
        stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        request
    });
    let directory = tempfile::tempdir().unwrap();
    let profile = [0x41; 32];
    let secure: Arc<dyn SecureStore> =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile));
    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        mutation_test_client("authority-a", "lineage-a", 1)
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
    let conversation = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").unwrap();
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").unwrap();
    let token = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000999").unwrap();
    let mut lease = core
        .prepare_mutation(
            MutationRequest::submit_task_run_with_identity(
                token,
                conversation,
                workspace,
                "managed task".to_owned(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .unwrap();
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Indeterminate { timestamp: 2 },
    )
    .unwrap();

    let recovered = core
        .recover_managed_task_run(&token.to_string())
        .await
        .unwrap();
    assert_eq!(recovered.status, "accepted");
    assert_eq!(
        recovered.task_run_id.as_deref(),
        Some("018f2e3a-7000-7000-8000-000000000904")
    );
    assert_eq!(recovered.stream_version, Some(2));
    assert_eq!(
        recovered.workspace_id.as_deref(),
        Some("018f2e3a-7000-7000-8000-000000000902")
    );
    assert_eq!(
        recovered.conversation_id.as_deref(),
        Some("018f2e3a-7000-7000-8000-000000000901")
    );
    assert!(
        server
            .await
            .unwrap()
            .starts_with("POST /v1/commands/reconcile HTTP/1.1")
    );
}

#[tokio::test]
async fn managed_start_rejects_invalid_text_and_stale_runtime_generation() {
    let directory = tempfile::tempdir().unwrap();
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .unwrap();
    let workspace = "018f2e3a-7000-7000-8000-000000000902";
    let conversation = "018f2e3a-7000-7000-8000-000000000901";
    let token = "018f2e3a-7000-7000-8000-000000000999";
    assert!(matches!(
        core.start_managed_task_run(workspace, conversation, " \n".to_owned(), 1, token)
            .await,
        Err(AppCoreError::InvalidMutation)
    ));
    assert!(matches!(
        core.start_managed_task_run(workspace, conversation, "task".to_owned(), 2, token)
            .await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
}

#[test]
fn managed_preflight_reuses_one_pending_token_for_same_native_scope() {
    let directory = tempfile::tempdir().unwrap();
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .unwrap();
    let runtime = replay::StableRuntimeIdentity::from_client(
        &core.live_runtime_client().unwrap(),
    );
    let intent = |workspace: &str, token: &str| ManagedTaskRunIntent {
        runtime: runtime.clone(),
        project_id: "018f2e3a-7000-7000-8000-000000000903".to_owned(),
        workspace_id: workspace.to_owned(),
        conversation_id: "018f2e3a-7000-7000-8000-000000000901".to_owned(),
        generation: 1,
        recovery_token: token.to_owned(),
    };
    let first = core
        .ensure_managed_intent(intent(
            "018f2e3a-7000-7000-8000-000000000902",
            "018f2e3a-7000-7000-8000-000000000999",
        ))
        .unwrap();
    let repeated = core
        .ensure_managed_intent(intent(
            "018f2e3a-7000-7000-8000-000000000902",
            "018f2e3a-7000-7000-8000-000000000998",
        ))
        .unwrap();
    assert_eq!(first, repeated);
    let next_scope = core
        .ensure_managed_intent(intent(
            "018f2e3a-7000-7000-8000-000000000904",
            "018f2e3a-7000-7000-8000-000000000997",
        ))
        .unwrap();
    assert_ne!(first, next_scope);
    assert!(core
        .validate_managed_intent(
            &runtime,
            "018f2e3a-7000-7000-8000-000000000902",
            "018f2e3a-7000-7000-8000-000000000901",
            1,
            &first,
        )
        .is_ok());
    assert!(core
        .validate_managed_intent(
            &runtime,
            "018f2e3a-7000-7000-8000-000000000904",
            "018f2e3a-7000-7000-8000-000000000901",
            1,
            &next_scope,
        )
        .is_ok());
    for index in 0..(MANAGED_ACTIVE_INTENT_LIMIT - 2) {
        let workspace = format!("018f2e3a-7000-7000-8000-{:012x}", 1000 + index);
        let token = format!("018f2e3a-7000-7000-8000-{:012x}", 2000 + index);
        core.ensure_managed_intent(intent(&workspace, &token)).unwrap();
    }
    assert!(matches!(
        core.ensure_managed_intent(intent(
            "018f2e3a-7000-7000-8000-000000000990",
            "018f2e3a-7000-7000-8000-000000000991",
        )),
        Err(AppCoreError::MutationUnavailable)
    ));
    assert!(core
        .validate_managed_intent(
            &runtime,
            "018f2e3a-7000-7000-8000-000000000902",
            "018f2e3a-7000-7000-8000-000000000901",
            1,
            &first,
        )
        .is_ok());
}

#[test]
fn accepted_managed_token_rejects_runtime_principal_and_scope_rebinding() {
    let directory = tempfile::tempdir().unwrap();
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .unwrap();
    let runtime = replay::StableRuntimeIdentity::from_client(&core.live_runtime_client().unwrap());
    let workspace = "018f2e3a-7000-7000-8000-000000000902";
    let conversation = "018f2e3a-7000-7000-8000-000000000901";
    let token = "018f2e3a-7000-7000-8000-000000000999";
    core.ensure_managed_intent(ManagedTaskRunIntent {
        runtime: runtime.clone(),
        project_id: "018f2e3a-7000-7000-8000-000000000903".to_owned(),
        workspace_id: workspace.to_owned(),
        conversation_id: conversation.to_owned(),
        generation: 1,
        recovery_token: token.to_owned(),
    })
    .unwrap();
    core.mark_managed_token_accepted(token, &runtime, workspace, conversation, 1)
        .unwrap();
    assert!(core
        .validate_managed_intent(&runtime, workspace, conversation, 1, token)
        .is_ok());
    let mut other_principal = mutation_test_client("authority-a", "lineage-a", 1)
        .session_info()
        .clone();
    other_principal.principal_id = "different-principal".to_owned();
    let other_client = runne_runtime_client::mock_authenticated_runtime_client(
        "http://127.0.0.1:1",
        other_principal,
    )
    .unwrap();
    let changed_principal = replay::StableRuntimeIdentity::from_client(&other_client);
    assert!(core
        .validate_managed_intent(&changed_principal, workspace, conversation, 1, token)
        .is_err());
    assert!(core
        .validate_managed_intent(
            &runtime,
            "018f2e3a-7000-7000-8000-000000000920",
            conversation,
            1,
            token,
        )
        .is_err());
    assert!(core
        .validate_managed_intent(&runtime, workspace, "018f2e3a-7000-7000-8000-000000000920", 1, token)
        .is_err());
}

#[tokio::test]
async fn managed_lease_rejects_semantic_predecessor_key_before_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .unwrap();
    let conversation = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").unwrap();
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").unwrap();
    let predecessor = core
        .prepare_mutation(
            MutationRequest::submit_task_run(
                conversation,
                workspace,
                "same semantic request".to_owned(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let issued_token = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000999").unwrap();
    let lease = core
        .prepare_mutation(
            MutationRequest::submit_task_run_with_identity(
                issued_token,
                conversation,
                workspace,
                "same semantic request".to_owned(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(lease.anchored_record.idempotency_key(), issued_token.to_string());
    assert_eq!(
        lease.anchored_record.idempotency_key(),
        predecessor.anchored_record.idempotency_key()
    );
    assert!(matches!(
        validate_managed_lease_identity(&lease, &issued_token.to_string()),
        Err(AppCoreError::MutationUnavailable)
    ));
    assert_eq!(
        lease.anchored_record.disposition(),
        runne_local_store::ClientMutationDisposition::Prepared
    );
}
