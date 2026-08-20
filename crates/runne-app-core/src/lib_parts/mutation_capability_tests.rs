const CAP_WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000951";

fn base_caps_client(origin: &str) -> AuthenticatedRuntimeClient {
    runne_runtime_client::mock_authenticated_runtime_client(
        origin,
        runne_runtime_client::RuntimeSessionInfo {
            profile_id: "gocode-ui-client/2".into(),
            schema_hash: runne_runtime_client::GOLDEN_BUNDLE_HASH.into(),
            runtime_version: "test".into(),
            capabilities: runne_runtime_client::REQUIRED_RUNTIME_CAPABILITIES
                .iter().map(ToString::to_string).collect(),
            authority_id: "authority-a".into(), principal_id: "principal".into(),
            event_log_lineage_id: "lineage-a".into(), daemon_instance_id: "daemon".into(),
            launch_generation: 1, session_id: "session-1".into(), authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".into(), certificate_sha256: "11".repeat(32),
            capability_digest: "22".repeat(32),
        },
    ).expect("client")
}

fn cap_protected_admission() -> runne_api::ProtectedRootHandleAdmission {
    use runne_api::{
        LaunchSecret, RootAdmissionAuthenticator, RootAdmissionRequest, RootAdmissionVerificationContext, RootHandleControlFrame, RootHandleTransferAuthenticator,
        RootHandleTransferContext, RootHandleTransferOffer, RootHandleTransferReady,
        RootHandleTransferResult, WorkspaceId,
    };
    let workspace: WorkspaceId = CAP_WORKSPACE_ID.parse().expect("workspace id");
    let context = RootHandleTransferContext::new(
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2],
        1, 10, 11, 1_000, workspace, 1, [4; 16], 100, 30_100,
    ).expect("context");
    let keys = RootHandleTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([7; 32]).expect("secret").derive_keys(),
    );
    let offer = RootHandleTransferOffer::new(context.clone(), 1, &keys).expect("offer");
    let ready = RootHandleTransferReady::new(&offer, &keys);
    let raw = RootAdmissionAuthenticator::from_protected_activation(&LaunchSecret::from_bytes([8; 32]).expect("secret").derive_keys())
        .issue(RootAdmissionRequest::new(RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 3, 1, 100).expect("context"), workspace, 1, [4; 32], offer.digest(), [5; 16], 30_100).expect("request"))
        .expect("raw admission");
    let frame = RootHandleControlFrame::Result(RootHandleTransferResult::admitted(&ready, raw, &keys));
    let runne_api::VerifiedRootHandleControlFrame::Result(result) = RootHandleControlFrame::decode_and_verify(
        &frame.encode_frame(), &keys, &context, 2, 100,
    ).expect("verified result") else { unreachable!() };
    result.into_protected_admission().expect("provenance admission")
}

#[tokio::test]
async fn root_bind_requires_protected_capabilities() {
    let origin = "http://127.0.0.1:1";
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        base_caps_client(origin),
    ).expect("core");
    let result = core.prepare_open_selected_workspace(
        CAP_WORKSPACE_ID.parse().expect("workspace"), 1, cap_protected_admission(),
    ).await;
    assert!(matches!(result, Err(AppCoreError::RuntimeUnavailable)));
}

#[test]
fn admission_binding_digest_is_included_in_semantic_digest() {
    let workspace_id = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000952").expect("workspace id");
    let admission = cap_protected_admission();
    let request1 = MutationRequest::for_conversation(
        runne_local_store::MutationOperation::WorkspaceBindRoot,
        MutationTarget::try_new(
            runne_local_store::MutationOperation::WorkspaceBindRoot,
            runne_local_store::MutationTargetKind::Workspace,
            runne_local_store::BoundedCanonicalId::parse(workspace_id.to_string().as_bytes()).expect("bounded"),
        ).expect("target"),
        1,
        CanonicalMutationCommand::BindWorkspaceRoot { workspace_id, admission_digest: admission.admission_digest() },
        CommandIdentity::new(CanonicalId::now_v7(), "key1".to_string()).expect("identity"),
        "key1".to_string(),
    );
    let request2 = MutationRequest::for_conversation(
        runne_local_store::MutationOperation::WorkspaceBindRoot,
        MutationTarget::try_new(
            runne_local_store::MutationOperation::WorkspaceBindRoot,
            runne_local_store::MutationTargetKind::Workspace,
            runne_local_store::BoundedCanonicalId::parse(workspace_id.to_string().as_bytes()).expect("bounded"),
        ).expect("target"),
        1,
        CanonicalMutationCommand::BindWorkspaceRoot { workspace_id, admission_digest: [0xFF; 32] },
        CommandIdentity::new(CanonicalId::now_v7(), "key2".to_string()).expect("identity"),
        "key2".to_string(),
    );
    assert_ne!(request1.semantic_digest(), request2.semantic_digest());
}
