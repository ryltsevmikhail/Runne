#[tokio::test]
async fn text_only_create_dispatches_scope_through_the_protected_conversation_api() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let conversation_id = CanonicalId::now_v7();
    let workspace_id = CanonicalId::now_v7();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request");
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).await.expect("read");
        let request = String::from_utf8_lossy(&bytes[..count]).into_owned();
        let body = format!(
            r#"{{"conversationId":"{conversation_id}","workspaceId":"{workspace_id}","streamVersion":1,"committedAt":1}}"#
        );
        let response = format!(
            "HTTP/1.1 202 Accepted\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response");
        request
    });

    let directory = tempfile::tempdir().expect("directory");
    let session = mutation_test_client("text-only-authority", "text-only-lineage", 1)
        .session_info()
        .clone();
    let client = runne_runtime_client::mock_authenticated_runtime_client(&origin, session)
        .expect("runtime client");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), client)
        .expect("core");
    let lease = core
        .prepare_mutation(
            MutationRequest::create_text_only_conversation(conversation_id, workspace_id)
                .expect("TextOnly create"),
        )
        .await
        .expect("prepare");
    core.send_exact_command(&lease, false)
        .await
        .expect("dispatch");
    let request = server.await.expect("request capture");
    assert!(request.starts_with("POST /v1/conversations HTTP/1.1"));
    assert!(request.contains(&format!(
        r#"{{"conversationId":"{conversation_id}","workspaceId":"{workspace_id}","scope":"text_only"}}"#
    )));
}
