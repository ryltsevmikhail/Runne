use runne_runtime_client::{
    CanonicalId, CommandIdentity, CommandReconciliationDisposition, CommandReconciliationOutcome,
    CommandReconciliationRequest, ConversationGenerationFailureReason, ConversationTextRejection,
    PROTECTED_RUNTIME_CAPABILITIES, RuntimeSessionInfo, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[path = "command_reconciliation/error_responses.rs"]
mod error_responses;
#[path = "command_reconciliation/response_limits.rs"]
mod response_limits;
#[path = "command_reconciliation/taskrun_failure_reasons.rs"]
mod taskrun_failure_reasons;

fn identity() -> CommandIdentity {
    CommandIdentity::new(
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000301").unwrap(),
        "reconcile-test",
    )
    .unwrap()
}

#[tokio::test]
async fn rejected_terminal_is_fully_parsed_and_correlated() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let body = r#"{"disposition":"durably_recorded","outcome":{"operation":"generate_conversation_text","terminal":"rejected","conversationId":"018f2e3a-7000-7000-8000-000000000303","taskRunId":"018f2e3a-7000-7000-8000-000000000304","attemptId":"018f2e3a-7000-7000-8000-000000000305","conversationStreamVersion":3,"taskRunStreamVersion":5,"userMessage":{"messageId":"018f2e3a-7000-7000-8000-000000000306","role":"user","taskRunId":"018f2e3a-7000-7000-8000-000000000304","attemptId":"018f2e3a-7000-7000-8000-000000000305","text":"hello","committedAt":1},"reservedAssistantMessageId":"018f2e3a-7000-7000-8000-000000000307","reason":"provider_output_rejected"}}"#;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let request = CommandReconciliationRequest::generate_conversation_text(
        identity(),
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000303").unwrap(),
        1,
        "hello",
    )
    .unwrap();
    let expected = ConversationTextRejection {
        conversation_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000303").unwrap(),
        task_run_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000304").unwrap(),
        attempt_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000305").unwrap(),
        conversation_stream_version: 3,
        task_run_stream_version: 5,
        user_message: runne_runtime_client::ConversationMessage {
            message_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000306").unwrap(),
            role: runne_runtime_client::ConversationMessageRole::User,
            task_run_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000304").unwrap(),
            attempt_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000305").unwrap(),
            text: "hello".into(),
            committed_at: 1,
        },
        reserved_assistant_message_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000307")
            .unwrap(),
        reason: ConversationGenerationFailureReason::ProviderOutputRejected,
    };
    assert_eq!(
        client.reconcile_command(request).await.unwrap(),
        CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::ConversationTextRejected(Box::new(expected))
        )
    );
    server.await.unwrap();
}

#[tokio::test]
async fn completed_and_prohibited_terminals_remain_distinct_and_fully_typed() {
    let completed = terminal_body(
        "completed",
        r#","assistantMessage":{"messageId":"018f2e3a-7000-7000-8000-000000000307","role":"assistant","taskRunId":"018f2e3a-7000-7000-8000-000000000304","attemptId":"018f2e3a-7000-7000-8000-000000000305","text":"answer","committedAt":2}"#,
    );
    let prohibited = terminal_body(
        "prohibited_input_rejected",
        r#","reservedAssistantMessageId":"018f2e3a-7000-7000-8000-000000000307","reason":"provider_output_rejected""#,
    );
    for (body, prohibited) in [(completed, false), (prohibited, true)] {
        let (origin, server) = serve(body).await;
        let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
        let outcome = client.reconcile_command(text_request()).await.unwrap();
        assert!(matches!(
            (prohibited, outcome),
            (
                false,
                CommandReconciliationDisposition::DurablyRecorded(
                    CommandReconciliationOutcome::ConversationTextCompleted(_)
                )
            ) | (
                true,
                CommandReconciliationDisposition::DurablyRecorded(
                    CommandReconciliationOutcome::ConversationTextProhibitedInputRejected(_)
                )
            )
        ));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_terminal_fields_are_invalid_responses() {
    let valid = terminal_body(
        "rejected",
        r#","reservedAssistantMessageId":"018f2e3a-7000-7000-8000-000000000307","reason":"provider_output_rejected""#,
    );
    let wrong = "018f2e3a-7000-7000-8000-000000000399";
    let cases = [
        valid.replace(CONVERSATION_ID, wrong),
        valid.replace(
            "\"conversationStreamVersion\":3",
            "\"conversationStreamVersion\":2",
        ),
        valid.replace("\"taskRunStreamVersion\":5", "\"taskRunStreamVersion\":4"),
        valid.replace("\"role\":\"user\"", "\"role\":\"assistant\""),
        valid.replace("\"text\":\"hello\"", "\"text\":\"bye\""),
        valid.replace(
            "\"role\":\"user\",\"taskRunId\":\"018f2e3a-7000-7000-8000-000000000304\"",
            &format!("\"role\":\"user\",\"taskRunId\":\"{wrong}\""),
        ),
        valid.replace(
            "\"role\":\"user\",\"taskRunId\":\"018f2e3a-7000-7000-8000-000000000304\",\"attemptId\":\"018f2e3a-7000-7000-8000-000000000305\"",
            &format!("\"role\":\"user\",\"taskRunId\":\"018f2e3a-7000-7000-8000-000000000304\",\"attemptId\":\"{wrong}\""),
        ),
        valid.replace(
            "018f2e3a-7000-7000-8000-000000000307",
            "018f2e3a-7000-7000-8000-000000000306",
        ),
        valid.replace("\"reason\":", "\"unknown\":true,\"reason\":"),
        valid.replace("\"taskRunId\":", "\"taskrunId\":"),
        valid.replace(
            "\"reason\":\"provider_output_rejected\"",
            "\"reason\":\"provider_output_rejected\",\"reason\":\"provider_output_rejected\"",
        ),
        valid.replace(
            "\"reservedAssistantMessageId\":\"018f2e3a-7000-7000-8000-000000000307\",",
            "",
        ),
        valid.replace(
            "\"terminal\":\"rejected\"",
            "\"terminal\":\"future_terminal\"",
        ),
        valid.replace("provider_output_rejected", "future_reason"),
        valid.replace(
            &format!("\"reservedAssistantMessageId\":\"{ASSISTANT_ID}\""),
            "\"reservedAssistantMessageId\":null",
        ),
        valid.replace(
            "\"userMessage\":",
            "\"assistantMessage\":null,\"userMessage\":"),
        valid.replace("generate_conversation_text", "archive_project"),
    ];
    for (case, body) in cases.into_iter().enumerate() {
        let (origin, server) = serve(body).await;
        let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
        let result = client.reconcile_command(text_request()).await;
        assert!(
            matches!(result, Err(ref error) if error.kind() == runne_runtime_client::RuntimeApiErrorKind::InvalidResponse),
            "case {case}: {result:?}"
        );
        server.await.unwrap();
    }
}

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000303";
const ASSISTANT_ID: &str = "018f2e3a-7000-7000-8000-000000000307";

fn text_request() -> CommandReconciliationRequest {
    CommandReconciliationRequest::generate_conversation_text(
        identity(),
        CanonicalId::parse(CONVERSATION_ID).unwrap(),
        1,
        "hello",
    )
    .unwrap()
}

fn terminal_body(terminal: &str, tail: &str) -> String {
    format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"generate_conversation_text","terminal":"{terminal}","conversationId":"{CONVERSATION_ID}","taskRunId":"018f2e3a-7000-7000-8000-000000000304","attemptId":"018f2e3a-7000-7000-8000-000000000305","conversationStreamVersion":3,"taskRunStreamVersion":5,"userMessage":{{"messageId":"018f2e3a-7000-7000-8000-000000000306","role":"user","taskRunId":"018f2e3a-7000-7000-8000-000000000304","attemptId":"018f2e3a-7000-7000-8000-000000000305","text":"hello","committedAt":1}}{tail}}}}}"#
    )
}

async fn serve(body: String) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream.write_all(format!("HTTP/1.1 200 OK\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    });
    (origin, server)
}

#[tokio::test]
async fn durable_project_receipt_is_correlated_to_the_original_witness() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let body = r#"{"disposition":"durably_recorded","outcome":{"operation":"archive_project","projectId":"018f2e3a-7000-7000-8000-000000000302","newVersion":2}}"#;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let request = CommandReconciliationRequest::archive_project(
        identity(),
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000302").unwrap(),
        1,
    )
    .unwrap();
    assert!(matches!(
        client.reconcile_command(request).await.unwrap(),
        CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::ProjectArchived(_)
        )
    ));
    server.await.unwrap();
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

#[tokio::test]
async fn reconciliation_posts_exact_identity_witness_and_requires_no_store() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 4096];
        let count = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
        assert!(request.contains("authorization: GocodeSession "));
        assert!(request.contains("x-command-id: 018f2e3a-7000-7000-8000-000000000301"));
        assert!(request.contains("idempotency-key: reconcile-test"));
        assert!(request.contains(r#"{"operation":"archive_project","projectId":"018f2e3a-7000-7000-8000-000000000302","expectedVersion":1}"#), "{request}");
        let body = r#"{"disposition":"not_committed_retryable"}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let request = CommandReconciliationRequest::archive_project(
        identity(),
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000302").unwrap(),
        1,
    )
    .unwrap();

    assert_eq!(
        client.reconcile_command(request).await.unwrap(),
        CommandReconciliationDisposition::not_committed_retryable()
    );
    server.await.unwrap();
}
