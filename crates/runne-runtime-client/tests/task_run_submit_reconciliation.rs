use runne_runtime_client::{
    CanonicalId, CommandIdentity, CommandReconciliationOutcome, CommandReconciliationRequest,
    PROTECTED_RUNTIME_CAPABILITIES, RuntimeSessionInfo, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const CONVERSATION: &str = "018f2e3a-7000-7000-8000-000000000304";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000303";
const TASK_RUN: &str = "018f2e3a-7000-7000-8000-000000000305";

#[tokio::test]
async fn prompt_reconciliation_serializes_exact_input_and_redacts_debug() {
    let request = CommandReconciliationRequest::submit_task_run(
        identity(),
        id(CONVERSATION),
        id(WORKSPACE),
        "private prompt",
    )
    .expect("valid prompt");
    assert!(!format!("{request:?}").contains("private prompt"));
    let (origin, server) = serve(
        response_body(),
        format!(
            r#"{{"operation":"submit_task_run","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}","prompt":"private prompt"}}"#
        ),
    )
    .await;
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let outcome = client.reconcile_command(request).await.unwrap();
    assert!(matches!(
        outcome,
        runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::TaskRunSubmitted(_)
        )
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn historical_promptless_reconciliation_keeps_the_legacy_payload() {
    let request = CommandReconciliationRequest::submit_task_run_legacy(
        identity(),
        id(CONVERSATION),
        id(WORKSPACE),
    );
    let (origin, server) = serve(
        response_body(),
        format!(
            r#"{{"operation":"submit_task_run","conversationId":"{CONVERSATION}","workspaceId":"{WORKSPACE}"}}"#
        ),
    )
    .await;
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let outcome = client.reconcile_command(request).await.unwrap();
    assert!(matches!(
        outcome,
        runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::TaskRunSubmitted(_)
        )
    ));
    server.await.unwrap();
}

async fn serve(body: String, expected_request: String) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let count = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.contains(&expected_request), "{request}");
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    (origin, server)
}

fn response_body() -> String {
    format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"submit_task_run","taskRunId":"{TASK_RUN}","newVersion":2}}}}"#
    )
}

fn id(value: &str) -> CanonicalId {
    CanonicalId::parse(value).unwrap()
}

fn identity() -> CommandIdentity {
    CommandIdentity::new(id("018f2e3a-7000-7000-8000-000000000301"), "reconcile-test").unwrap()
}

fn session() -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".into(),
        schema_hash: "test".into(),
        runtime_version: "test".into(),
        capabilities: PROTECTED_RUNTIME_CAPABILITIES
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
