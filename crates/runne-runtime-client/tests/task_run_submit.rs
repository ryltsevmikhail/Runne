use std::net::Ipv4Addr;

use runne_runtime_client::{
    CanonicalId, CommandIdentity, REQUIRED_RUNTIME_CAPABILITIES, RuntimeApiErrorKind,
    RuntimeSessionInfo, SubmitTaskRunRequest, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-000000000210";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000242";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000243";
const COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000212";

#[tokio::test]
async fn task_run_submit_uses_authenticated_command_and_validates_ack() {
    let body = format!(
        "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"streamVersion\":2,\"transition\":\"submitted\",\"attemptId\":null,\"terminalResult\":null}}"
    );
    let (request, acknowledgement) = submit_exchange(202, "Accepted", &body, "submitted").await;

    assert!(request.starts_with("POST /v1/task-runs/submit HTTP/1.1"));
    assert!(request.contains("authorization: GocodeSession "));
    assert!(request.contains("x-command-id: 018f2e3a-7000-7000-8000-000000000212"));
    assert!(request.contains("idempotency-key: submit-1"));
    assert!(request.contains(&format!(
        "{{\"conversationId\":\"{CONVERSATION_ID}\",\"workspaceId\":\"{WORKSPACE_ID}\"}}"
    )));
    let acknowledgement = acknowledgement.expect("submit acknowledgement");
    assert_eq!(
        acknowledgement.task_run_id(),
        CanonicalId::parse(TASK_RUN_ID).expect("task run ID")
    );
    assert_eq!(acknowledgement.stream_version(), 2);
}

#[tokio::test]
async fn task_run_submit_rejects_non_submit_transitions() {
    for (transition, extra_field) in [
        ("\"transition\":\"queued\"", ""),
        (
            "\"transition\":\"submitted\"",
            ",\"attemptId\":\"018f2e3a-7000-7000-8000-000000000211\"",
        ),
        (
            "\"transition\":\"submitted\"",
            ",\"terminalResult\":{\"type\":\"success\"}",
        ),
    ] {
        let body = format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"streamVersion\":2,{transition},\"attemptId\":null,\"terminalResult\":null{extra_field}}}"
        );
        let (_, acknowledgement) = submit_exchange(202, "Accepted", &body, "unused").await;
        assert_eq!(
            acknowledgement.expect_err("ack must be rejected").kind(),
            RuntimeApiErrorKind::InvalidResponse,
            "transition {transition} with {extra_field}"
        );
    }
}

async fn submit_exchange(
    status: u16,
    reason: &str,
    body: &str,
    _label: &str,
) -> (
    String,
    Result<
        runne_runtime_client::TaskRunSubmitAcknowledgement,
        runne_runtime_client::RuntimeApiError,
    >,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let response = response(status, reason, body);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.expect("read");
            assert_ne!(read, 0, "request headers");
            request.extend_from_slice(&buffer[..read]);
        }
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response");
        String::from_utf8(request).expect("request UTF-8")
    });
    let client = mock_authenticated_runtime_client(&origin, session()).expect("client");
    let identity = CommandIdentity::new(
        CanonicalId::parse(COMMAND_ID).expect("command ID"),
        "submit-1",
    )
    .expect("identity");
    let outcome = client
        .submit_task_run(SubmitTaskRunRequest::new(
            identity,
            CanonicalId::parse(CONVERSATION_ID).expect("conversation ID"),
            CanonicalId::parse(WORKSPACE_ID).expect("workspace ID"),
        ))
        .await;
    let request = server.await.expect("server");
    (request, outcome)
}

fn response(status: u16, reason: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn session() -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".to_owned(),
        schema_hash: "test".to_owned(),
        runtime_version: "test".to_owned(),
        capabilities: REQUIRED_RUNTIME_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        authority_id: "authority".to_owned(),
        principal_id: "principal".to_owned(),
        event_log_lineage_id: "lineage".to_owned(),
        daemon_instance_id: "daemon".to_owned(),
        launch_generation: 1,
        session_id: "session".to_owned(),
        authorization_epoch: 1,
        sensitivity_ceiling: "sensitive".to_owned(),
        certificate_sha256: "certificate".to_owned(),
        capability_digest: "digest".to_owned(),
    }
}
