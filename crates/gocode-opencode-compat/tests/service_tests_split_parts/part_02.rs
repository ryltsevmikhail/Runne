#[tokio::test]
async fn golden_session_create_request_and_response_are_byte_exact() {
    let request_bytes = include_bytes!("../../../../docs/golden/session-create-request-v1.json");
    assert_eq!(
        request_bytes,
        b"{\"title\":\"Golden Session\",\"workspaceID\":\"workspace-wire-id\"}\n"
    );
    let wire: GoldenCreateRequest = serde_json::from_slice(request_bytes).unwrap();
    let key = SessionBindingKey {
        session_id: OpenCodeSessionId::new("ses_golden").unwrap(),
        profile_id: ProfileId::new("opencode-baseline-inventory").unwrap(),
        profile_revision: 2,
        runtime_authority_id: BindingRuntimeAuthorityId::new("runtime-golden").unwrap(),
    };
    let request = SessionCreateRequestContext {
        conversation_id: UUID_A.parse().unwrap(),
        workspace_id: UUID_B.parse().unwrap(),
        command_id: UUID_C.parse().unwrap(),
        idempotency_key: IdempotencyKey::new("golden-session-create").unwrap(),
        api_context: ApiCommandContext {
            principal: ApiPrincipalId::new("golden-principal").unwrap(),
            actor: ApiActor::new("golden-actor").unwrap(),
            response_seed: ResponseSeed {
                project_id: "golden-project".into(),
                directory: "/tmp/golden".into(),
                path: Some("/tmp/golden".into()),
                version: "1.0".into(),
                workspace_id: Some(wire.workspace_id.clone()),
            },
        },
    };
    let response = service(MockBindingStore::default(), MockHost::succeeds())
        .create_session(
            key,
            &request,
            OpenCodeCreateInput {
                title: Some(wire.title),
                workspace_id: Some(wire.workspace_id),
                parent_id: None,
                agent: None,
                model: None,
                metadata: None,
                permission: None,
            },
        )
        .await
        .unwrap();

    let actual = serde_json::to_vec(response.as_value()).unwrap();
    let expected = include_bytes!("../../../../docs/golden/session-create-response-v1.json");
    assert_eq!(actual, expected.strip_suffix(b"\n").unwrap());
}

#[tokio::test]
async fn success_commits_a_schema_valid_response() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let result = service(binding.clone(), host.clone())
        .create_session(key(), &request(), input())
        .await
        .unwrap();

    assert_eq!(host.calls(), 1);
    assert_eq!(result.as_value()["id"], "ses_baseline_1");
    assert_eq!(result.as_value()["workspaceID"], "wire-workspace");
    assert!(matches!(
        binding.status(&key()),
        Some(SessionBindingStatus::Committed { .. })
    ));
}

#[tokio::test]
async fn committed_retry_returns_stored_response_without_host_call() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let sut = service(binding, host.clone());
    let first = sut
        .create_session(key(), &request(), input())
        .await
        .unwrap();
    let retry = sut
        .create_session(key(), &request(), input())
        .await
        .unwrap();

    assert_eq!(first, retry);
    assert_eq!(host.calls(), 1);
}

#[tokio::test]
async fn host_failure_keeps_binding_pending() {
    let binding = MockBindingStore::default();
    let host = MockHost::fails(HostError::Timeout);
    let error = service(binding.clone(), host.clone())
        .create_session(key(), &request(), input())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SessionCreateError::Host(HostError::Timeout)
    ));
    assert_eq!(host.calls(), 1);
    assert!(matches!(
        binding.status(&key()),
        Some(SessionBindingStatus::Pending { .. })
    ));
}

#[tokio::test]
async fn recovery_rebuilds_response_after_host_success_and_commit_failure() {
    let binding = MockBindingStore::default();
    binding.set_commit_failure(BindingError::StorageFailure);
    let host = MockHost::succeeds();
    let sut = service(binding.clone(), host.clone());
    let create_input = input();
    let error = sut
        .create_session(key(), &request(), create_input)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SessionCreateError::Binding(BindingError::StorageFailure)
    ));

    binding.clear_commit_failure();
    let recovered = sut.recover_pending(key()).await.unwrap();

    assert_eq!(host.calls(), 2);
    assert_eq!(recovered.as_value()["title"], "New session");
    assert_eq!(recovered.as_value()["workspaceID"], "wire-workspace");
    assert!(matches!(
        binding.status(&key()),
        Some(SessionBindingStatus::Committed { .. })
    ));
}

#[tokio::test]
async fn context_or_fingerprint_conflict_never_calls_host() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let sut = service(binding.clone(), host.clone());
    sut.create_session(key(), &request(), input())
        .await
        .unwrap();

    let mut changed = input();
    changed.title = Some("Different title".into());
    let error = sut
        .create_session(key(), &request(), changed)
        .await
        .unwrap_err();
    assert!(matches!(error, SessionCreateError::ContextConflict { .. }));
    assert_eq!(host.calls(), 1);
    assert_eq!(binding.ensure_calls(), 2);
}

#[tokio::test]
async fn unsupported_field_has_no_binding_or_host_side_effect() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let mut rejected = input();
    rejected.permission = Some(serde_json::json!([]));
    let error = service(binding.clone(), host.clone())
        .create_session(key(), &request(), rejected)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SessionCreateError::UnsupportedField {
            field: "permission"
        }
    ));
    assert_eq!(binding.ensure_calls(), 0);
    assert_eq!(host.calls(), 0);
}

#[tokio::test]
async fn oversized_durable_response_is_rejected_before_binding_or_host() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let mut oversized = input();
    oversized.title = Some("x".repeat(gocode_api::OpenCodeSessionInfo::MAX_WIRE_BYTES));
    let error = service(binding.clone(), host.clone())
        .create_session(key(), &request(), oversized)
        .await
        .unwrap_err();

    assert!(matches!(error, SessionCreateError::Validation(_)));
    assert_eq!(binding.ensure_calls(), 0);
    assert_eq!(host.calls(), 0);
}

#[tokio::test]
async fn profile_mismatch_has_no_binding_or_host_side_effect() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let mut wrong_key = key();
    wrong_key.profile_revision = 1;
    let error = service(binding.clone(), host.clone())
        .create_session(wrong_key, &request(), input())
        .await
        .unwrap_err();

    assert!(matches!(error, SessionCreateError::ProfileMismatch { .. }));
    assert_eq!(binding.ensure_calls(), 0);
    assert_eq!(host.calls(), 0);
}

#[tokio::test]
async fn revision_one_is_rejected_even_when_service_and_key_match() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let mut revision_one_key = key();
    revision_one_key.profile_revision = 1;
    let sut = OpenCodeSessionCreateService::new(
        binding.clone(),
        host.clone(),
        ProfileRef {
            profile_id: ProfileId::new("opencode-baseline-inventory").expect("profile"),
            profile_revision: 1,
        },
        schema(),
    );

    let error = sut
        .create_session(revision_one_key, &request(), input())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SessionCreateError::UnsupportedProfile { .. }
    ));
    assert_eq!(binding.ensure_calls(), 0);
    assert_eq!(host.calls(), 0);
}

struct ImpossibleCommittedStore;
