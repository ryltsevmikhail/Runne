use runne_runtime_client::{
    CanonicalId, CommandIdentity, EditorLaunchTargetDto, OpenEditorCommandRequest,
    PROTECTED_RUNTIME_CAPABILITIES, RuntimeSessionInfo, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000404";
const COMMAND: &str = "018f2e3a-7000-7000-8000-000000000405";

fn session() -> RuntimeSessionInfo {
    let mut capabilities = PROTECTED_RUNTIME_CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    capabilities.push("workspace.editor.open.v1".to_owned());
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".into(),
        schema_hash: "test".into(),
        runtime_version: "test".into(),
        capabilities,
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
async fn editor_client_sends_only_scoped_reference_and_target() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
        }
        let body = format!("{{\"workspaceId\":\"{WORKSPACE}\",\"target\":\"system_default\"}}");
        stream
            .write_all(response(202, &body).as_bytes())
            .await
            .unwrap();
        String::from_utf8(request).unwrap()
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let identity = CommandIdentity::new(CanonicalId::parse(COMMAND).unwrap(), "editor-1").unwrap();
    let receipt = client
        .open_workspace_editor(
            OpenEditorCommandRequest::new(
                identity,
                CanonicalId::parse(WORKSPACE).unwrap(),
                "src/main.rs",
                EditorLaunchTargetDto::SystemDefault,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let request = server.await.unwrap();
    assert!(
        request.starts_with(
            "POST /v1/workspaces/018f2e3a-7000-7000-8000-000000000404/editor HTTP/1.1"
        )
    );
    assert!(request.contains("\"relativePath\":\"src/main.rs\""));
    assert!(request.contains("\"target\":\"system_default\""));
    assert_eq!(
        receipt.workspace_id(),
        CanonicalId::parse(WORKSPACE).unwrap()
    );
}

fn response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}
