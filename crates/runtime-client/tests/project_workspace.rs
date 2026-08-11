use gocode_runtime_client::{
    BindWorkspaceRootRequest, CanonicalId, CommandIdentity, CreateProjectRequest,
    CreateWorkspaceRequest, ExistingProjectRequest, ExistingWorkspaceRequest,
    REQUIRED_RUNTIME_CAPABILITIES, RootAdmissionToken, RuntimeApiErrorKind, RuntimeSessionInfo,
    mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn identity() -> CommandIdentity {
    CommandIdentity::new(
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000301").unwrap(),
        "project-workspace-test",
    )
    .unwrap()
}

fn id() -> CanonicalId {
    CanonicalId::parse("018f2e3a-7000-7000-8000-000000000302").unwrap()
}

#[test]
fn project_workspace_requests_reject_invalid_names_and_versions() {
    assert_eq!(
        CreateProjectRequest::new(identity(), id(), "\u{0000}")
            .unwrap_err()
            .kind(),
        RuntimeApiErrorKind::InvalidRequest
    );
    assert_eq!(
        ExistingProjectRequest::new(identity(), id(), 0)
            .unwrap_err()
            .kind(),
        RuntimeApiErrorKind::InvalidRequest
    );
}

#[test]
fn root_admission_token_is_opaque_redacted_and_v2_only() {
    let token =
        RootAdmissionToken::parse(format!("gocode-root-admission-v2.{}", "A".repeat(343))).unwrap();
    assert_eq!(format!("{token:?}"), "RootAdmissionToken([REDACTED])");
    assert_eq!(
        RootAdmissionToken::parse("gocode-root-admission-v1.abc")
            .unwrap_err()
            .kind(),
        RuntimeApiErrorKind::InvalidRequest
    );
    assert!(BindWorkspaceRootRequest::new(identity(), id(), 1, token).is_ok());
}

#[test]
fn capability_wave_is_exactly_required_by_the_client() {
    for capability in ["project.list.v1", "project.restore.v1"] {
        assert!(REQUIRED_RUNTIME_CAPABILITIES.contains(&capability));
    }
    assert!(REQUIRED_RUNTIME_CAPABILITIES.contains(&"workspace.bind_root.v2"));
}

fn session() -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/1".into(),
        schema_hash: "test".into(),
        runtime_version: "test".into(),
        capabilities: REQUIRED_RUNTIME_CAPABILITIES
            .iter()
            .map(|value| (*value).into())
            .collect(),
        authority_id: "authority".into(),
        principal_id: "principal".into(),
        event_log_lineage_id: "lineage".into(),
        daemon_instance_id: "daemon".into(),
        launch_generation: 1,
        session_id: "session".into(),
        authorization_epoch: 1,
        sensitivity_ceiling: "sensitive".into(),
        certificate_sha256: "certificate".into(),
        capability_digest: "digest".into(),
    }
}

#[tokio::test]
async fn delete_project_uses_authenticated_delete_body_headers_and_closed_errors() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        for status in [202, 409, 404] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let count = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(
                request.starts_with(
                    "DELETE /v1/projects/018f2e3a-7000-7000-8000-000000000302 HTTP/1.1"
                )
            );
            assert!(request.contains("authorization: GocodeSession "));
            assert!(request.contains("x-command-id: 018f2e3a-7000-7000-8000-000000000301"));
            assert!(request.contains("idempotency-key: project-workspace-test"));
            assert!(request.contains(r#"{"expectedVersion":1}"#));
            let request_id = "018f2e3a-7000-7000-8000-000000000399";
            let body = if status == 202 {
                format!(
                    r#"{{"projectId":"{ID}","newVersion":2}}"#,
                    ID = "018f2e3a-7000-7000-8000-000000000302"
                )
            } else {
                format!(
                    r#"{{"code":"project_workspace_{}","requestId":"{request_id}"}}"#,
                    if status == 409 {
                        "conflict"
                    } else {
                        "not_found"
                    }
                )
            };
            stream.write_all(format!("HTTP/1.1 {status} test\r\ncontent-type: application/json\r\nx-request-id: {request_id}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        }
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let request = ExistingProjectRequest::new(identity(), id(), 1).unwrap();
    assert_eq!(
        client
            .delete_project(request.clone())
            .await
            .unwrap()
            .new_version(),
        2
    );
    assert_eq!(
        client
            .delete_project(request.clone())
            .await
            .unwrap_err()
            .kind(),
        RuntimeApiErrorKind::Conflict
    );
    assert_eq!(
        client.delete_project(request).await.unwrap_err().kind(),
        RuntimeApiErrorKind::NotFound
    );
    server.await.unwrap();
}

#[path = "project_workspace/adversarial.rs"]
mod adversarial;
