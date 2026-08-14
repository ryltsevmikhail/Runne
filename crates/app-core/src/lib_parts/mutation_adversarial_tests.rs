use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, oneshot},
};

fn adversarial_client(origin: &str) -> AuthenticatedRuntimeClient {
    gocode_runtime_client::mock_authenticated_runtime_client(
        origin,
        gocode_runtime_client::RuntimeSessionInfo {
            profile_id: "gocode-ui-client/2".into(),
            schema_hash: gocode_runtime_client::GOLDEN_BUNDLE_HASH.into(),
            runtime_version: "test".into(),
            capabilities: gocode_runtime_client::REQUIRED_RUNTIME_CAPABILITIES
                .iter().map(ToString::to_string).collect(),
            authority_id: "authority-a".into(), principal_id: "principal".into(),
            event_log_lineage_id: "lineage-a".into(), daemon_instance_id: "daemon".into(),
            launch_generation: 1, session_id: "session-1".into(), authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".into(), certificate_sha256: "11".repeat(32),
            capability_digest: "22".repeat(32),
        },
    ).expect("loopback client")
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut bytes = vec![0; 8192];
    let count = stream.read(&mut bytes).await.expect("request");
    String::from_utf8(bytes[..count].to_vec()).expect("ascii request")
}

async fn project_ack(stream: &mut tokio::net::TcpStream, id: CanonicalId, version: u64) {
    let body = format!(r#"{{"projectId":"{id}","newVersion":{version}}}"#);
    stream.write_all(format!("HTTP/1.1 202 Accepted\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("ack");
}

async fn reconciled_project(stream: &mut tokio::net::TcpStream, id: CanonicalId, version: u64) {
    let body = format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{id}","newVersion":{version}}}}}"#);
    stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("reconcile");
}

fn project_request() -> MutationRequest {
    MutationRequest::create_project(
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000801").expect("project id"),
        "Project".into(),
    ).expect("request")
}

#[tokio::test]
async fn canonical_outcome_reconciles_only_and_rejects_changed_receipt() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let request = project_request();
    let duplicate = request.clone();
    let CanonicalMutationCommand::CreateProject { project_id, .. } = request.semantic_command else {
        unreachable!()
    };
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("first mutation");
        let first_request = read_request(&mut first).await;
        project_ack(&mut first, project_id, 1).await;
        let (mut initial_reconcile, _) = listener.accept().await.expect("initial reconcile");
        let initial_reconcile_request = read_request(&mut initial_reconcile).await;
        reconciled_project(&mut initial_reconcile, project_id, 1).await;
        let (mut receipt, _) = listener.accept().await.expect("terminal reconcile");
        let receipt_request = read_request(&mut receipt).await;
        reconciled_project(&mut receipt, project_id, 2).await;
        (first_request, initial_reconcile_request, receipt_request)
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), adversarial_client(&origin)).expect("core");
    let first = core.prepare_mutation(request).await.expect("prepare first");
    assert!(matches!(core.dispatch_prepared_mutation(first).await, Ok(MutationDispatchResult::Project(_))));
    let receipt = core.prepare_mutation(duplicate).await.expect("terminal receipt");
    assert_eq!(receipt.anchored_record.disposition(), gocode_local_store::ClientMutationDisposition::CanonicalOutcome);
    assert!(matches!(core.dispatch_prepared_mutation(receipt).await, Err(AppCoreError::MutationUnavailable)));
    let (first, initial_reconcile, receipt) = server.await.expect("server");
    assert!(first.starts_with("POST /v1/projects HTTP/1.1"));
    assert!(initial_reconcile.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(receipt.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}

#[tokio::test]
async fn changed_semantic_digest_conflicts_without_a_network_call() {
    let directory = tempfile::tempdir().expect("directory");
    let mut changed = project_request();
    let original = changed.clone();
    changed.semantic_command = CanonicalMutationCommand::CreateProject {
        project_id: match changed.semantic_command { CanonicalMutationCommand::CreateProject { project_id, .. } => project_id, _ => unreachable!() },
        display_name: "Changed".into(),
    };
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), mutation_test_client("authority-a", "lineage-a", 1)).expect("core");
    core.prepare_mutation(original).await.expect("prepare");
    assert_eq!(core.prepare_mutation(changed).await.unwrap_err().to_string(), AppCoreError::MutationUnavailable.to_string());
}

#[tokio::test]
async fn secure_anchor_failure_after_runtime_ack_hides_the_ack() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let (seen_tx, mut seen_rx) = mpsc::channel(1);
    let (release_tx, release_rx) = oneshot::channel();
    let project_id = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000801").expect("project id");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request");
        let _request = read_request(&mut stream).await;
        seen_tx.send(()).await.expect("seen");
        release_rx.await.expect("release");
        project_ack(&mut stream, project_id, 1).await;
    });
    let profile = [0x52; 32];
    let secure = std::sync::Arc::new(gocode_secure_store::test_support::DeterministicSecureStore::new(profile));
    let directory = tempfile::tempdir().expect("directory");
    let core = std::sync::Arc::new(AppCore::open_with_test_runtime_secure(&directory.path().join("profile.sqlite3"), adversarial_client(&origin), secure.clone(), profile).expect("core"));
    let lease = core.prepare_mutation(project_request()).await.expect("prepare");
    let dispatched = { let core = std::sync::Arc::clone(&core); tokio::spawn(async move { core.dispatch_prepared_mutation(lease).await }) };
    seen_rx.recv().await.expect("send observed");
    secure.fail_next_advance();
    release_tx.send(()).expect("release ack");
    assert!(matches!(dispatched.await.expect("dispatch task"), Err(AppCoreError::MutationUnavailable)));
    server.await.expect("server");
}

#[tokio::test]
async fn secure_anchor_failure_before_dispatching_sends_nothing() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let profile = [0x53; 32];
    let secure = std::sync::Arc::new(gocode_secure_store::test_support::DeterministicSecureStore::new(profile));
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_test_runtime_secure(&directory.path().join("profile.sqlite3"), adversarial_client(&origin), secure.clone(), profile).expect("core");
    let lease = core.prepare_mutation(project_request()).await.expect("prepare");
    secure.fail_next_advance();
    assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::MutationUnavailable)));
    assert!(tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept()).await.is_err());
}

#[tokio::test]
async fn secure_anchor_failure_before_canonical_outcome_hides_result_and_leaves_observing() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project_id = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000801").expect("project id");
    let server = tokio::spawn(async move {
        let (mut mutation, _) = listener.accept().await.expect("mutation");
        let _request = read_request(&mut mutation).await;
        project_ack(&mut mutation, project_id, 1).await;
        let (mut reconcile, _) = listener.accept().await.expect("reconcile");
        let _request = read_request(&mut reconcile).await;
        reconciled_project(&mut reconcile, project_id, 1).await;
    });
    let profile = [0x54; 32];
    let secure = std::sync::Arc::new(gocode_secure_store::test_support::DeterministicSecureStore::new(profile));
    let directory = tempfile::tempdir().expect("directory");
    let core = std::sync::Arc::new(AppCore::open_with_test_runtime_secure(&directory.path().join("profile.sqlite3"), adversarial_client(&origin), secure.clone(), profile).expect("core"));
    core.mutation_test_hold_before_canonical.store(true, std::sync::atomic::Ordering::Release);
    let request = project_request();
    let retry = request.clone();
    let lease = core.prepare_mutation(request).await.expect("prepare");
    let reached = core.mutation_test_before_canonical_reached.notified();
    let dispatched = { let core = std::sync::Arc::clone(&core); tokio::spawn(async move { core.dispatch_prepared_mutation(lease).await }) };
    tokio::time::timeout(std::time::Duration::from_secs(2), reached)
        .await
        .expect("canonical hook reached");
    secure.fail_next_advance();
    core.mutation_test_continue_canonical.notify_one();
    assert!(matches!(dispatched.await.expect("dispatch task"), Err(AppCoreError::MutationUnavailable)));
    drop(core);
    let core = AppCore::open_with_test_runtime_secure(
        &directory.path().join("profile.sqlite3"), adversarial_client(&origin), secure, profile,
    ).expect("recover core");
    let recovery = core.prepare_mutation(retry).await.expect("recovery receipt");
    assert_eq!(recovery.anchored_record.disposition(), gocode_local_store::ClientMutationDisposition::Observing);
    server.await.expect("server");
}

#[tokio::test]
async fn connection_loss_retries_the_original_authenticated_command() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project_id = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000801").expect("project id");
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("first");
        let first_request = read_request(&mut first).await;
        drop(first);
        let (mut second, _) = listener.accept().await.expect("reconcile");
        let second_request = read_request(&mut second).await;
        reconciled_project(&mut second, project_id, 1).await;
        (first_request, second_request)
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), adversarial_client(&origin)).expect("core");
    let request = project_request();
    let lease = core.prepare_mutation(request).await.expect("prepare");
    assert!(matches!(
        core.dispatch_prepared_mutation(lease).await,
        Ok(MutationDispatchResult::Project(_))
    ));
    let (first, second) = server.await.expect("server");
    assert!(first.starts_with("POST /v1/projects HTTP/1.1"));
    assert!(second.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}
