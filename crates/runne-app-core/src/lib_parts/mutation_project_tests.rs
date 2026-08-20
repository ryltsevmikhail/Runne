fn proj_request() -> MutationRequest {
    MutationRequest::create_project(
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").expect("project id"),
        "Project".into(),
    ).expect("request")
}

fn proj_ack(id: &str, version: u64) -> String {
    format!(r#"{{"projectId":"{id}","newVersion":{version}}}"#)
}

async fn proj_server(listener: tokio::net::TcpListener, replies: Vec<(u16, String)>) -> Vec<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut requests = Vec::new();
    for (status, body) in replies {
        let (mut stream, _) = listener.accept().await.expect("request");
        let mut bytes = vec![0; 8192];
        let count = stream.read(&mut bytes).await.expect("read");
        requests.push(String::from_utf8(bytes[..count].to_vec()).expect("ascii"));
        let response = format!(
            "HTTP/1.1 {status} test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.expect("response");
    }
    requests
}

#[tokio::test]
async fn create_project_rejects_wrong_ack_version() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project_id = "018f2e3a-7000-7000-8000-000000000901";
    let server = tokio::spawn(proj_server(listener, vec![
        (202, proj_ack(project_id, 1)),
        (200, format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{project_id}","newVersion":7}}}}"#)),
    ]));
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        runne_runtime_client::mock_authenticated_runtime_client(
            &origin,
            runne_runtime_client::RuntimeSessionInfo {
                profile_id: "gocode-ui-client/2".into(),
                schema_hash: runne_runtime_client::GOLDEN_BUNDLE_HASH.into(),
                runtime_version: "test".into(),
                capabilities: runne_runtime_client::REQUIRED_RUNTIME_CAPABILITIES.iter().map(ToString::to_string).collect(),
                authority_id: "authority-a".into(), principal_id: "principal".into(),
                event_log_lineage_id: "lineage-a".into(), daemon_instance_id: "daemon".into(),
                launch_generation: 1, session_id: "session-1".into(), authorization_epoch: 1,
                sensitivity_ceiling: "sensitive".into(), certificate_sha256: "11".repeat(32),
                capability_digest: "22".repeat(32),
            },
        ).expect("client"),
    ).expect("core");
    let request = proj_request();
    let retry = request.clone();
    let lease = core.prepare_mutation(request).await.expect("prepare");
    assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::MutationUnavailable)));
    server.await.expect("server");
    let recovered = core.prepare_mutation(retry).await.expect("recovery");
    assert_ne!(recovered.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::CanonicalOutcome);
}

#[tokio::test]
async fn create_project_rejects_wrong_ack_id() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let wrong_id = "018f2e3a-7000-7000-8000-000000000999";
    let project_id = "018f2e3a-7000-7000-8000-000000000901";
    let server = tokio::spawn(proj_server(listener, vec![
        (202, proj_ack(project_id, 1)),
        (200, format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{wrong_id}","newVersion":1}}}}"#)),
    ]));
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        runne_runtime_client::mock_authenticated_runtime_client(
            &origin,
            runne_runtime_client::RuntimeSessionInfo {
                profile_id: "gocode-ui-client/2".into(),
                schema_hash: runne_runtime_client::GOLDEN_BUNDLE_HASH.into(),
                runtime_version: "test".into(),
                capabilities: runne_runtime_client::REQUIRED_RUNTIME_CAPABILITIES.iter().map(ToString::to_string).collect(),
                authority_id: "authority-a".into(), principal_id: "principal".into(),
                event_log_lineage_id: "lineage-a".into(), daemon_instance_id: "daemon".into(),
                launch_generation: 1, session_id: "session-1".into(), authorization_epoch: 1,
                sensitivity_ceiling: "sensitive".into(), certificate_sha256: "11".repeat(32),
                capability_digest: "22".repeat(32),
            },
        ).expect("client"),
    ).expect("core");
    let request = proj_request();
    let retry = request.clone();
    let lease = core.prepare_mutation(request).await.expect("prepare");
    assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::MutationUnavailable)));
    server.await.expect("server");
    core.set_runtime_availability(RuntimeAvailability::Live).expect("reconnect");
    let recovered = core.prepare_mutation(retry).await.expect("recovery");
    assert_eq!(recovered.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::ManualResolution);
}
