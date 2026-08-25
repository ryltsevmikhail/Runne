use runne_runtime_client::{
    CanonicalId, PROTECTED_RUNTIME_CAPABILITIES, RuntimeSessionInfo, WorkspaceChangeKindDto,
    WorkspaceDiffLineKindDto, mock_authenticated_runtime_client,
};
use tokio::{io::AsyncWriteExt, net::TcpListener};

const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000302";

fn session() -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".into(),
        schema_hash: "test".into(),
        runtime_version: "test".into(),
        capabilities: PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
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
async fn list_workspace_changes_requires_capability_and_strictly_decodes_entries() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 4096];
        let count = tokio::io::AsyncReadExt::read(&mut stream, &mut request)
            .await
            .unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.starts_with(&format!("GET /v1/workspaces/{WORKSPACE}/changes")));
        let body =
            r#"{"items":[{"path":"src/main.rs","kind":"modified","additions":2,"deletions":1}]}"#;
        stream
            .write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes())
            .await
            .unwrap();
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let changes = client
        .list_workspace_changes(CanonicalId::parse(WORKSPACE).unwrap(), 10)
        .await
        .unwrap();
    assert_eq!(
        changes.entries()[0].kind(),
        WorkspaceChangeKindDto::Modified
    );
    assert_eq!(changes.entries()[0].path(), "src/main.rs");
    server.await.unwrap();
}

#[tokio::test]
async fn read_workspace_diff_decodes_bounded_hunks() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 4096];
        let count = tokio::io::AsyncReadExt::read(&mut stream, &mut request)
            .await
            .unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.starts_with(&format!("GET /v1/workspaces/{WORKSPACE}/diff")));
        let body = r#"{"path":"src/main.rs","kind":"modified","hunks":[{"oldStart":1,"oldLines":1,"newStart":1,"newLines":1,"lines":[{"kind":"removed","text":"old"},{"kind":"added","text":"new"}]}],"truncated":false}"#;
        stream
            .write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes())
            .await
            .unwrap();
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let diff = client
        .read_workspace_diff(CanonicalId::parse(WORKSPACE).unwrap(), "src/main.rs")
        .await
        .unwrap();
    assert_eq!(
        diff.hunks()[0].lines()[0].kind(),
        WorkspaceDiffLineKindDto::Removed
    );
    assert_eq!(diff.hunks()[0].lines()[1].text(), "new");
    server.await.unwrap();
}
