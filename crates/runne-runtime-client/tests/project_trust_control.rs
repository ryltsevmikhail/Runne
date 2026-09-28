use runne_runtime_client::{
    CanonicalId, PROTECTED_RUNTIME_CAPABILITIES, ProjectTrustControlRequestDto,
    ProjectTrustDecisionDto, ProjectTrustStatusDto, RuntimeApiErrorKind, RuntimeSessionInfo,
    mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000302";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000304";

fn session() -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".into(),
        schema_hash: "test".into(),
        runtime_version: "test".into(),
        capabilities: PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|x| (*x).into())
            .collect(),
        authority_id: "authority".into(),
        principal_id: "local-owner".into(),
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
async fn lost_post_reply_is_unknown_then_readback_does_not_redispatch() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut post, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        let count = post.read(&mut bytes).await.unwrap();
        let request = String::from_utf8_lossy(&bytes[..count]);
        assert!(request.starts_with(&format!(
            "POST /v1/projects/{PROJECT}/workspaces/{WORKSPACE}/trust HTTP/1.1"
        )));
        assert!(request.contains("authorization: GocodeSession "));
        assert!(request.contains(r#""action":"confirm_project""#));
        // The server models a durable commit followed by a lost response.
        drop(post);

        let (mut get, _) = listener.accept().await.unwrap();
        let count = get.read(&mut bytes).await.unwrap();
        let request = String::from_utf8_lossy(&bytes[..count]);
        assert!(request.starts_with(&format!(
            "GET /v1/projects/{PROJECT}/workspaces/{WORKSPACE}/trust HTTP/1.1"
        )));
        let body = format!(
            r#"{{"projectId":"{PROJECT}","projectName":"project","projectVersion":"1","workspaceId":"{WORKSPACE}","workspaceName":"workspace","workspaceVersion":"2","status":"trusted","managedDenyMask":0,"provenance":"user","epoch":"1","revision":"1","rootAdmissionVersion":"1"}}"#
        );
        get.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let request = ProjectTrustControlRequestDto {
        project_id: CanonicalId::parse(PROJECT).unwrap(),
        workspace_id: CanonicalId::parse(WORKSPACE).unwrap(),
        decision: ProjectTrustDecisionDto::ConfirmProject,
        expected_epoch: 1,
        expected_revision: 0,
        expected_project_version: 1,
        expected_workspace_version: 2,
        expected_root_admission_version: Some(1),
    };
    assert_eq!(
        client
            .decide_project_trust(request)
            .await
            .unwrap_err()
            .kind(),
        RuntimeApiErrorKind::UnknownAfterSend
    );
    let readback = client
        .get_project_trust(request.project_id, request.workspace_id)
        .await
        .unwrap();
    assert_eq!(readback.status(), ProjectTrustStatusDto::Trusted);
    assert_eq!(readback.revision(), 1);
    server.await.unwrap();
}
