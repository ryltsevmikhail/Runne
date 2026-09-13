#[tokio::test]
async fn rename_restart_recovers_durable_result_without_resending() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000813").expect("project");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("reconcile");
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).await.expect("read");
        let request = String::from_utf8_lossy(&bytes[..count]).into_owned();
        let body = format!(
            r#"{{"disposition":"durably_recorded","outcome":{{"operation":"rename_project","projectId":"{project}","newVersion":2}}}}"#
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response");
        request
    });
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");
    let profile = [0x89; 32];
    let secure: std::sync::Arc<dyn runne_secure_store::SecureStore> = std::sync::Arc::new(
        runne_secure_store::test_support::DeterministicSecureStore::new(profile),
    );
    let core = AppCore::open_bundled_anchored(&path, secure.clone(), profile).expect("core");
    let start = core.begin_bundled_runtime_start().await.expect("start");
    core.install_bundled_runtime_client(start, protected_workspace_client(&origin))
        .await
        .expect("installed");
    let mut lease = core
        .prepare_mutation(
            MutationRequest::rename_project(project, 1, "Renamed".into()).expect("request"),
        )
        .await
        .expect("prepared");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatching");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Indeterminate { timestamp: 2 },
    )
    .expect("reconciling");
    drop(core);
    let resumed = AppCore::open_bundled_anchored(&path, secure, profile).expect("resumed");
    let restart = resumed
        .begin_bundled_runtime_start()
        .await
        .expect("restart");
    assert_eq!(
        resumed
            .install_bundled_runtime_client(restart, protected_workspace_client(&origin))
            .await
            .expect("live"),
        RuntimeAvailability::Live
    );
    assert_eq!(
        resumed.runtime_availability().expect("live"),
        RuntimeAvailability::Live
    );
    let request = server.await.expect("server");
    assert!(request.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(!request.contains("POST /v1/projects"));
}
