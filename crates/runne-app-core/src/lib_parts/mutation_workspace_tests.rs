const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000851";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8000-000000000852";
const WRONG_ID: &str = "018f2e3a-7000-7000-8000-000000000853";

enum WorkspaceReply {
    Json(u16, String),
    Close,
}

fn workspace_snapshot(id: &str, version: u64, open: bool) -> String {
    format!(
        r#"{{"workspaceId":"{id}","projectId":"{PROJECT_ID}","displayName":"workspace","version":{version},"open":{open}}}"#
    )
}

fn workspace_ack(id: &str, version: u64) -> String {
    format!(r#"{{"workspaceId":"{id}","newVersion":{version}}}"#)
}

fn workspace_reconcile(operation: &str, id: &str, version: u64) -> String {
    format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"{operation}","workspaceId":"{id}","newVersion":{version}}}}}"#)
}

async fn workspace_server(listener: TcpListener, replies: Vec<WorkspaceReply>, expected: usize) -> Vec<String> {
    let mut requests = Vec::with_capacity(replies.len());
    for reply in replies.into_iter().take(expected) {
        let (mut stream, _) = listener.accept().await.expect("request");
        let mut bytes = vec![0; 8192];
        let count = stream.read(&mut bytes).await.expect("read request");
        requests.push(String::from_utf8(bytes[..count].to_vec()).expect("request is ascii"));
        if let WorkspaceReply::Json(status, body) = reply {
            let response = format!(
                "HTTP/1.1 {status} test\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("response");
        }
    }
    requests
}

fn protected_admission() -> runne_api::ProtectedRootHandleAdmission {
    use runne_api::{
        LaunchSecret, RootAdmissionAuthenticator, RootAdmissionRequest, RootAdmissionVerificationContext, RootHandleControlFrame, RootHandleTransferAuthenticator,
        RootHandleTransferContext, RootHandleTransferOffer, RootHandleTransferReady,
        RootHandleTransferResult, WorkspaceId,
    };

    let workspace: WorkspaceId = WORKSPACE_ID.parse().expect("workspace id");
    let context = RootHandleTransferContext::new(
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2],
        1, 10, 11, 1_000, workspace, 1, [4; 16], 100, 30_100,
    )
    .expect("transfer context");
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
    )
    .expect("verified transfer result") else {
        unreachable!("result frame")
    };
    result.into_protected_admission().expect("provenance admission")
}

fn protected_workspace_client(origin: &str) -> AuthenticatedRuntimeClient {
    let capabilities = runne_runtime_client::PROTECTED_RUNTIME_CAPABILITIES
        .iter().map(ToString::to_string).collect::<Vec<_>>();
    let capability_digest = protected_capability_digest(&capabilities);
    runne_runtime_client::mock_protected_authenticated_runtime_client(
        origin,
        runne_runtime_client::RuntimeSessionInfo {
            profile_id: "gocode-ui-client/2".into(),
            schema_hash: runne_runtime_client::GOLDEN_BUNDLE_HASH.into(),
            runtime_version: "test".into(),
            capabilities,
            authority_id: "authority-a".into(), principal_id: "principal".into(),
            event_log_lineage_id: "lineage-a".into(), daemon_instance_id: "daemon".into(),
            launch_generation: 1, session_id: "session-1".into(), authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".into(), certificate_sha256: "11".repeat(32),
            capability_digest,
        },
    )
    .expect("client")
}

fn protected_capability_digest(capabilities: &[String]) -> String {
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/local-runtime/capability-digest/v1\0");
    digest.update(u32::try_from(capabilities.len()).expect("length").to_be_bytes());
    for capability in capabilities {
        digest.update(u32::try_from(capability.len()).expect("length").to_be_bytes());
        digest.update(capability.as_bytes());
    }
    hex::encode(digest.finalize())
}

async fn protected_workspace_core(origin: &str, directory: &tempfile::TempDir) -> AppCore {
    let profile = [0x85; 32];
    let secure: std::sync::Arc<dyn runne_secure_store::SecureStore> = std::sync::Arc::new(
        runne_secure_store::test_support::DeterministicSecureStore::new(profile),
    );
    let core = AppCore::open_bundled_anchored(&directory.path().join("profile.sqlite3"), secure, profile)
        .expect("core");
    let lease = core.begin_bundled_runtime_start().await.expect("start");
    core.install_bundled_runtime_client(lease, protected_workspace_client(origin)).await.expect("install");
    core
}

#[tokio::test]
async fn composite_rejects_wrong_acknowledgements_and_final_snapshots_after_possible_bind_send() {
    let cases = [
        vec![
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 2)),
            WorkspaceReply::Json(200, workspace_reconcile("bind_workspace_root", WRONG_ID, 2)),
        ],
        vec![
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 2)),
            WorkspaceReply::Json(200, workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 2)),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 3)),
            WorkspaceReply::Json(200, workspace_reconcile("open_workspace", WORKSPACE_ID, 3)),
            WorkspaceReply::Json(200, workspace_snapshot(WRONG_ID, 3, true)),
        ],
        vec![
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 2)),
            WorkspaceReply::Json(200, workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 2)),
            WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 3)),
            WorkspaceReply::Json(200, workspace_reconcile("open_workspace", WORKSPACE_ID, 3)),
            WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 2, false)),
        ],
    ];
    for replies in cases {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let expected = replies.len();
        let server = tokio::spawn(workspace_server(listener, replies, expected));
        let directory = tempfile::tempdir().expect("directory");
        let core = protected_workspace_core(&origin, &directory).await;
        let mut prepared = core
            .prepare_open_selected_workspace(
                WORKSPACE_ID.parse().expect("workspace"), 1, protected_admission(),
            )
            .await
            .expect("prepare");
        let failure = core.dispatch_prepared_workspace_open(&mut prepared).await.expect_err("must reject");
        assert_eq!(failure.disposition(), NativeAuthorityDisposition::ReleaseWithoutReap);
        server.await.expect("server");
    }
}

#[tokio::test]
async fn composite_connection_loss_retries_the_exact_bind_without_global_reconnect() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(listener, vec![
        WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)),
        WorkspaceReply::Close,
        WorkspaceReply::Json(200, r#"{"disposition":"indeterminate"}"#.into()),
        WorkspaceReply::Json(200, workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 2)),
        WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 3)),
        WorkspaceReply::Json(200, workspace_reconcile("open_workspace", WORKSPACE_ID, 3)),
        WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 3, true)),
    ], 7));
    let directory = tempfile::tempdir().expect("directory");
    let core = protected_workspace_core(&origin, &directory).await;
    let mut prepared = core.prepare_open_selected_workspace(
        WORKSPACE_ID.parse().expect("workspace"), 1, protected_admission(),
    ).await.expect("prepare");
    assert_eq!(core.dispatch_prepared_workspace_open(&mut prepared).await.unwrap_err().disposition(), NativeAuthorityDisposition::ReleaseWithoutReap);
    let retry = core.dispatch_prepared_workspace_open(&mut prepared).await;
    assert!(retry.is_ok(), "retry failed: {retry:?}");
    let requests = server.await.expect("server");
    assert!(requests[1].starts_with(&format!(
        "POST /v1/workspaces/{WORKSPACE_ID}/root-bindings HTTP/1.1"
    )));
    assert!(requests[2].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(requests[3].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(requests[4].starts_with(&format!("POST /v1/workspaces/{WORKSPACE_ID}/open HTTP/1.1")));
}

#[tokio::test]
async fn restart_reconciles_the_original_open_without_a_second_open_post() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(listener, vec![
        WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)),
        WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 2)),
        WorkspaceReply::Json(200, workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 2)),
        WorkspaceReply::Close,
        WorkspaceReply::Json(200, r#"{"disposition":"indeterminate"}"#.into()),
        WorkspaceReply::Json(200, workspace_reconcile("open_workspace", WORKSPACE_ID, 3)),
    ], 6));
    let directory = tempfile::tempdir().expect("directory");
    let core = protected_workspace_core(&origin, &directory).await;
    let mut prepared = core.prepare_open_selected_workspace(
        WORKSPACE_ID.parse().expect("workspace"), 1, protected_admission(),
    ).await.expect("prepare");
    assert_eq!(core.dispatch_prepared_workspace_open(&mut prepared).await.unwrap_err().disposition(), NativeAuthorityDisposition::ReleaseWithoutReap);
    let lease = core.begin_bundled_runtime_restart().await.expect("restart");
    core.install_bundled_runtime_client(lease, protected_workspace_client(&origin))
        .await
        .expect("recovered");
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 6);
    assert_eq!(requests.iter().filter(|request| request.contains("/root-bindings")).count(), 1);
    assert_eq!(requests.iter().filter(|request| request.contains("/open HTTP/1.1")).count(), 1);
}

#[tokio::test]
async fn pre_bind_secure_failure_reaps_before_dispatch_without_a_bind_call() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(
        listener,
        vec![WorkspaceReply::Json(
            200,
            workspace_snapshot(WORKSPACE_ID, 1, false),
        )], 1,
    ));
    let profile = [0x85; 32];
    let secure = std::sync::Arc::new(
        runne_secure_store::test_support::DeterministicSecureStore::new(profile),
    );
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_bundled_anchored(
        &directory.path().join("profile.sqlite3"), secure.clone(), profile,
    ).expect("core");
    let lease = core.begin_bundled_runtime_start().await.expect("start");
    core.install_bundled_runtime_client(lease, protected_workspace_client(&origin)).await.expect("install");
    let mut prepared = core
        .prepare_open_selected_workspace(
            WORKSPACE_ID.parse().expect("workspace"),
            1,
            protected_admission(),
        )
        .await
        .expect("prepare");
    secure.fail_next_advance();
    let failure = core
        .dispatch_prepared_workspace_open(&mut prepared)
        .await
        .expect_err("secure failure");
    assert_eq!(failure.disposition(), NativeAuthorityDisposition::ReapBeforeDispatch);
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 1, "pre-bind failure issued a bind request");
}
