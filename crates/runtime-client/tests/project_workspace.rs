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
    let token = RootAdmissionToken::parse("gocode-root-admission-v2.AA").unwrap();
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
    assert!(!REQUIRED_RUNTIME_CAPABILITIES.contains(&"workspace.bind_root.v2"));
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

#[tokio::test]
async fn project_workspace_identity_mismatches_are_invalid_responses() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let wrong = "018f2e3a-7000-7000-8000-000000000303";
    let server = tokio::spawn(async move {
        for _ in 0..10 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let count = stream.read(&mut bytes).await.unwrap();
            let request = String::from_utf8_lossy(&bytes[..count]);
            let (status, body) = if request.starts_with("GET /v1/projects/") {
                (
                    200,
                    format!(
                        r#"{{"projectId":"{wrong}","displayName":"name","version":1,"archived":false}}"#
                    ),
                )
            } else if request.starts_with("GET /v1/workspaces/") {
                (
                    200,
                    format!(
                        r#"{{"workspaceId":"{wrong}","projectId":"{wrong}","displayName":"name","version":1,"open":false}}"#
                    ),
                )
            } else if request.starts_with("GET /v1/projects/") && request.contains("/workspaces") {
                (
                    200,
                    format!(
                        r#"{{"items":[{{"workspaceId":"{wrong}","projectId":"{wrong}","displayName":"name","version":1,"open":false}}],"nextCursor":null}}"#
                    ),
                )
            } else if request.contains("/v1/projects/") {
                (202, format!(r#"{{"projectId":"{wrong}","newVersion":2}}"#))
            } else {
                (
                    202,
                    format!(r#"{{"workspaceId":"{wrong}","newVersion":2}}"#),
                )
            };
            stream.write_all(format!("HTTP/1.1 {status} test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        }
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let project = id();
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000304").unwrap();
    let command = identity();
    for result in [
        client.get_project(project).await.map(|_| ()),
        client.get_workspace(workspace).await.map(|_| ()),
        client.list_workspaces(project, 1, None).await.map(|_| ()),
        client
            .create_project(CreateProjectRequest::new(command.clone(), project, "name").unwrap())
            .await
            .map(|_| ()),
        client
            .archive_project(ExistingProjectRequest::new(command.clone(), project, 1).unwrap())
            .await
            .map(|_| ()),
        client
            .restore_project(ExistingProjectRequest::new(command.clone(), project, 1).unwrap())
            .await
            .map(|_| ()),
        client
            .delete_project(ExistingProjectRequest::new(command.clone(), project, 1).unwrap())
            .await
            .map(|_| ()),
        client
            .create_workspace(
                CreateWorkspaceRequest::new(command.clone(), project, workspace, "name").unwrap(),
            )
            .await
            .map(|_| ()),
        client
            .open_workspace(ExistingWorkspaceRequest::new(command.clone(), workspace, 1).unwrap())
            .await
            .map(|_| ()),
        client
            .bind_workspace_root(
                BindWorkspaceRootRequest::new(
                    command,
                    workspace,
                    1,
                    RootAdmissionToken::parse("gocode-root-admission-v2.AA").unwrap(),
                )
                .unwrap(),
            )
            .await
            .map(|_| ()),
    ] {
        assert_eq!(
            result.unwrap_err().kind(),
            RuntimeApiErrorKind::InvalidResponse
        );
    }
    server.abort();
}
