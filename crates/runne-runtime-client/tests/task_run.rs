use std::net::Ipv4Addr;

use runne_runtime_client::{
    CanonicalId, REQUIRED_RUNTIME_CAPABILITIES, RuntimeApiErrorKind, RuntimeSessionInfo,
    TaskRunState, TaskRunTerminalResult, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-000000000210";
const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000211";

#[tokio::test]
async fn task_run_query_uses_authenticated_exact_get_and_decodes_running_snapshot() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.expect("read");
            assert_ne!(read, 0, "request headers");
            request.extend_from_slice(&buffer[..read]);
        }
        let body = format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"running\",\"streamVersion\":3,\"activeAttemptId\":\"{ATTEMPT_ID}\",\"terminalResult\":null}}"
        );
        stream
            .write_all(response(200, "OK", &body).as_bytes())
            .await
            .expect("response");
        String::from_utf8(request).expect("request UTF-8")
    });
    let client = mock_authenticated_runtime_client(&origin, session()).expect("client");
    let task_run_id = CanonicalId::parse(TASK_RUN_ID).expect("task run ID");

    let snapshot = client.get_task_run(task_run_id).await.expect("task run");
    let request = server.await.expect("server");
    assert!(request.starts_with(&format!("GET /v1/task-runs/{TASK_RUN_ID} HTTP/1.1")));
    assert!(request.contains("authorization: GocodeSession "));
    assert_eq!(snapshot.task_run_id(), task_run_id);
    assert_eq!(snapshot.state(), TaskRunState::Running);
    assert_eq!(
        snapshot.active_attempt_id(),
        CanonicalId::parse(ATTEMPT_ID).ok()
    );
}

#[tokio::test]
async fn task_run_snapshot_enforces_terminal_and_active_attempt_invariants() {
    let succeeded = query_snapshot(&format!(
        "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"succeeded\",\"streamVersion\":4,\"activeAttemptId\":null,\"terminalResult\":{{\"type\":\"failure\",\"reason\":\"settled failure\"}}}}"
    ))
    .await;
    assert_eq!(succeeded.state(), TaskRunState::Succeeded);
    assert_eq!(
        succeeded.terminal_result(),
        Some(&TaskRunTerminalResult::Failure {
            reason: "settled failure".to_owned()
        })
    );

    for state in [
        "running",
        "waiting",
        "retrying",
        "checkpointing",
        "reconciling",
    ] {
        assert!(
            query_snapshot_result(&snapshot_body(state, None))
                .await
                .is_err()
        );
        assert!(
            query_snapshot_result(&snapshot_body(state, Some(ATTEMPT_ID)))
                .await
                .is_ok()
        );
    }
    for state in [
        "created",
        "queued",
        "admitted",
        "failed",
        "cancelled",
        "budget_exhausted",
        "policy_denied",
        "unrecoverable",
    ] {
        assert!(
            query_snapshot_result(&snapshot_body(state, Some(ATTEMPT_ID)))
                .await
                .is_err()
        );
        assert!(
            query_snapshot_result(&snapshot_body(state, None))
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn task_run_snapshot_rejects_malformed_contract_shape() {
    for body in [
        format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"running\",\"streamVersion\":0,\"activeAttemptId\":\"{ATTEMPT_ID}\",\"terminalResult\":null}}"
        ),
        format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"created\",\"streamVersion\":4,\"terminalResult\":null}}"
        ),
        format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"created\",\"streamVersion\":4,\"activeAttemptId\":null}}"
        ),
        format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"succeeded\",\"streamVersion\":4,\"activeAttemptId\":null,\"terminalResult\":{{\"type\":\"failure\",\"reason\":\"\"}}}}"
        ),
    ] {
        assert!(query_snapshot_result(&body).await.is_err());
    }
}

#[tokio::test]
async fn task_run_errors_are_redacted_and_mapped() {
    let conflict = query_task_run_result(
        409,
        "task_run_conflict",
        "{\"code\":\"task_run_conflict\",\"requestId\":\"018f2e3a-7000-7000-8000-000000000212\"}",
    )
    .await
    .expect_err("task run conflict");
    assert_eq!(conflict.kind(), RuntimeApiErrorKind::Conflict);
    assert_eq!(
        conflict.request_id(),
        Some("018f2e3a-7000-7000-8000-000000000212")
    );

    let invariant = query_task_run_result(
        500,
        "runtime_invariant_violation",
        "{\"code\":\"runtime_invariant_violation\",\"requestId\":\"018f2e3a-7000-7000-8000-000000000213\"}",
    )
    .await
    .expect_err("runtime invariant violation");
    assert_eq!(invariant.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(invariant.request_id(), None);
}

async fn query_snapshot(body: &str) -> runne_runtime_client::TaskRunSnapshot {
    query_snapshot_result(body).await.expect("snapshot")
}

fn snapshot_body(state: &str, active_attempt_id: Option<&str>) -> String {
    let active_attempt_id =
        active_attempt_id.map_or_else(|| "null".to_owned(), |id| format!("\"{id}\""));
    format!(
        "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"{state}\",\"streamVersion\":4,\"activeAttemptId\":{active_attempt_id},\"terminalResult\":null}}"
    )
}

async fn query_snapshot_result(
    body: &str,
) -> Result<runne_runtime_client::TaskRunSnapshot, runne_runtime_client::RuntimeApiError> {
    query_task_run_result(200, "OK", body).await
}

async fn query_task_run_result(
    status: u16,
    reason: &str,
    body: &str,
) -> Result<runne_runtime_client::TaskRunSnapshot, runne_runtime_client::RuntimeApiError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let body = body.to_owned();
    let response = response(status, reason, &body);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.expect("request");
            assert_ne!(read, 0, "request headers");
            request.extend_from_slice(&buffer[..read]);
        }
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response");
    });
    mock_authenticated_runtime_client(&origin, session())
        .expect("client")
        .get_task_run(CanonicalId::parse(TASK_RUN_ID).expect("task run ID"))
        .await
}

fn response(status: u16, reason: &str, body: &str) -> String {
    let request_id_header = request_id(body)
        .map(|value| format!("x-request-id: {value}\r\n"))
        .unwrap_or_default();
    format!(
        "HTTP/1.1 {status} {reason}\r\n{request_id_header}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn request_id(body: &str) -> Option<&str> {
    let key = "\"requestId\":\"";
    let start = body.find(key)? + key.len();
    let end = body[start..].find('"')?;
    Some(&body[start..start + end])
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
