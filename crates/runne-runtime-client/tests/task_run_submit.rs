use std::net::Ipv4Addr;

use sha2::Digest;

use runne_runtime_client::{
    CanonicalId, CommandIdentity, EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH,
    REQUIRED_RUNTIME_CAPABILITIES, RuntimeApiErrorKind, RuntimeSessionInfo, SubmitTaskRunRequest,
    SubmitTaskRunV1Request, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-000000000210";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000242";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000243";
const COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000212";

#[test]
fn task_run_submit_request_rejects_empty_and_oversized_prompts() {
    let identity = CommandIdentity::new(
        CanonicalId::parse(COMMAND_ID).expect("command ID"),
        "submit-invalid",
    )
    .expect("identity");
    let conversation = CanonicalId::parse(CONVERSATION_ID).expect("conversation ID");
    let workspace = CanonicalId::parse(WORKSPACE_ID).expect("workspace ID");
    let valid = SubmitTaskRunRequest::new(
        identity.clone(),
        conversation,
        workspace,
        "private prompt".to_owned(),
    )
    .expect("valid prompt");
    assert!(!format!("{valid:?}").contains("private prompt"));
    assert_eq!(
        SubmitTaskRunRequest::new(identity.clone(), conversation, workspace, String::new())
            .expect_err("empty prompt is invalid")
            .kind(),
        RuntimeApiErrorKind::InvalidRequest
    );
    assert_eq!(
        SubmitTaskRunRequest::new(
            identity,
            conversation,
            workspace,
            "x".repeat(runne_api::MAX_TASK_RUN_PROMPT_BYTES + 1),
        )
        .expect_err("oversized prompt is invalid")
        .kind(),
        RuntimeApiErrorKind::InvalidRequest
    );
}

#[tokio::test]
async fn task_run_submit_uses_authenticated_command_and_validates_ack() {
    let body = format!(
        "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"streamVersion\":2,\"transition\":\"submitted\",\"attemptId\":null,\"terminalResult\":null}}"
    );
    let (request, acknowledgement) = submit_exchange(202, "Accepted", &body, "submitted").await;

    assert!(request.starts_with("POST /v2/task-runs/submit HTTP/1.1"));
    assert!(request.contains("authorization: GocodeSession "));
    assert!(request.contains("x-command-id: 018f2e3a-7000-7000-8000-000000000212"));
    assert!(request.contains("idempotency-key: submit-1"));
    assert!(request.contains(&format!(
        "{{\"conversationId\":\"{CONVERSATION_ID}\",\"workspaceId\":\"{WORKSPACE_ID}\",\"prompt\":\"fix bug\"}}"
    )));
    let acknowledgement = acknowledgement.expect("submit acknowledgement");
    assert_eq!(
        acknowledgement.task_run_id(),
        CanonicalId::parse(TASK_RUN_ID).expect("task run ID")
    );
    assert_eq!(acknowledgement.stream_version(), 2);
}

#[tokio::test]
async fn task_run_submit_v1_sends_ids_only() {
    let body = format!(
        "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"streamVersion\":2,\"transition\":\"submitted\",\"attemptId\":null,\"terminalResult\":null}}"
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let response = response(202, "Accepted", &body);
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
    let identity =
        CommandIdentity::new(CanonicalId::parse(COMMAND_ID).unwrap(), "v1-submit").unwrap();
    let ack = client
        .submit_task_run_v1(SubmitTaskRunV1Request::new(
            identity,
            CanonicalId::parse(CONVERSATION_ID).unwrap(),
            CanonicalId::parse(WORKSPACE_ID).unwrap(),
        ))
        .await
        .expect("v1 ack");
    let request = server.await.expect("server");
    assert!(request.starts_with("POST /v1/task-runs/submit HTTP/1.1"));
    assert!(request.contains(&format!(
        "{{\"conversationId\":\"{CONVERSATION_ID}\",\"workspaceId\":\"{WORKSPACE_ID}\"}}"
    )));
    assert!(!request.contains("prompt"));
    assert_eq!(ack.stream_version(), 2);
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

#[tokio::test]
async fn task_run_submit_rejects_wrong_nonzero_ack_versions() {
    for version in [1, 3, u64::MAX] {
        let body = format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"streamVersion\":{version},\"transition\":\"submitted\",\"attemptId\":null,\"terminalResult\":null}}"
        );
        let (_, result) = submit_exchange(202, "Accepted", &body, "wrong-version").await;
        assert_eq!(
            result
                .expect_err("wrong submit version must be rejected")
                .kind(),
            RuntimeApiErrorKind::InvalidResponse
        );
    }
}

#[tokio::test]
async fn task_run_submit_v1_rejects_wrong_nonzero_ack_version() {
    let body = format!(
        "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"streamVersion\":3,\"transition\":\"submitted\",\"attemptId\":null,\"terminalResult\":null}}"
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let response = response(202, "Accepted", &body);
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
    });
    let client = mock_authenticated_runtime_client(&origin, session()).expect("client");
    let identity =
        CommandIdentity::new(CanonicalId::parse(COMMAND_ID).unwrap(), "v1-wrong-version").unwrap();
    let result = client
        .submit_task_run_v1(SubmitTaskRunV1Request::new(
            identity,
            CanonicalId::parse(CONVERSATION_ID).unwrap(),
            CanonicalId::parse(WORKSPACE_ID).unwrap(),
        ))
        .await;
    server.await.expect("server");
    assert_eq!(
        result
            .expect_err("wrong v1 submit version must be rejected")
            .kind(),
        RuntimeApiErrorKind::InvalidResponse
    );
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
        .submit_task_run(
            SubmitTaskRunRequest::new(
                identity,
                CanonicalId::parse(CONVERSATION_ID).expect("conversation ID"),
                CanonicalId::parse(WORKSPACE_ID).expect("workspace ID"),
                "fix bug",
            )
            .expect("valid request"),
        )
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
    let capabilities = REQUIRED_RUNTIME_CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/local-runtime/capability-digest/v1\0");
    digest.update(u32::try_from(capabilities.len()).unwrap().to_be_bytes());
    for capability in &capabilities {
        digest.update(u32::try_from(capability.len()).unwrap().to_be_bytes());
        digest.update(capability.as_bytes());
    }
    RuntimeSessionInfo {
        profile_id: EXPECTED_BUNDLE_ID.to_owned(),
        schema_hash: GOLDEN_BUNDLE_HASH.to_owned(),
        runtime_version: "test".to_owned(),
        capabilities,
        authority_id: "authority".to_owned(),
        principal_id: "principal".to_owned(),
        event_log_lineage_id: "lineage".to_owned(),
        daemon_instance_id: "daemon".to_owned(),
        launch_generation: 1,
        session_id: "session".to_owned(),
        authorization_epoch: 1,
        sensitivity_ceiling: "sensitive".to_owned(),
        certificate_sha256: "certificate".to_owned(),
        capability_digest: hex::encode(digest.finalize()),
    }
}
