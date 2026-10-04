use super::*;

#[tokio::test]
async fn provider_execution_rejections_and_failures_are_typed() {
    for (wire_reason, expected_reason) in [
        (
            "provider_execution_rejected",
            ConversationGenerationFailureReason::ProviderExecutionRejected,
        ),
        (
            "provider_execution_failed",
            ConversationGenerationFailureReason::ProviderExecutionFailed,
        ),
        (
            "provider_accounting_unknown",
            ConversationGenerationFailureReason::ProviderAccountingUnknown,
        ),
    ] {
        let tail =
            format!(r#","reservedAssistantMessageId":"{ASSISTANT_ID}","reason":"{wire_reason}""#);
        let (origin, server) = serve(terminal_body("rejected", &tail)).await;
        let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
        let outcome = client.reconcile_command(text_request()).await.unwrap();
        assert!(matches!(
            outcome,
            CommandReconciliationDisposition::DurablyRecorded(
                CommandReconciliationOutcome::ConversationTextRejected(rejection)
            ) if rejection.reason == expected_reason
        ));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_generation_is_exactly_rejected_v6() {
    let cancelled = terminal_body(
        "rejected",
        &format!(r#","reservedAssistantMessageId":"{ASSISTANT_ID}","reason":"cancelled""#),
    )
    .replace("\"taskRunStreamVersion\":5", "\"taskRunStreamVersion\":6");
    let (origin, server) = serve(cancelled).await;
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let outcome = client.reconcile_command(text_request()).await.unwrap();
    assert!(matches!(
        outcome,
        CommandReconciliationDisposition::DurablyRecorded(
            CommandReconciliationOutcome::ConversationTextRejected(rejection)
        ) if rejection.task_run_stream_version == 6
            && rejection.reason == ConversationGenerationFailureReason::Cancelled
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn cancelled_reason_is_rejected_on_v5_or_non_rejected_v6() {
    let v5_cancelled = terminal_body(
        "rejected",
        &format!(r#","reservedAssistantMessageId":"{ASSISTANT_ID}","reason":"cancelled""#),
    );
    let v6_failure = terminal_body(
        "rejected",
        &format!(
            r#","reservedAssistantMessageId":"{ASSISTANT_ID}","reason":"provider_execution_failed""#
        ),
    )
    .replace("\"taskRunStreamVersion\":5", "\"taskRunStreamVersion\":6");
    let v6_completed = terminal_body(
        "completed",
        &format!(r#","assistantMessage":{{"messageId":"{ASSISTANT_ID}","role":"assistant","taskRunId":"018f2e3a-7000-7000-8000-000000000304","attemptId":"018f2e3a-7000-7000-8000-000000000305","text":"answer","committedAt":2}}"#),
    )
    .replace("\"taskRunStreamVersion\":5", "\"taskRunStreamVersion\":6");
    let v6_prohibited_cancelled = terminal_body(
        "prohibited_input_rejected",
        &format!(r#","reservedAssistantMessageId":"{ASSISTANT_ID}","reason":"cancelled""#),
    )
    .replace("\"taskRunStreamVersion\":5", "\"taskRunStreamVersion\":6");
    let v6_unknown = terminal_body(
        "rejected",
        &format!(r#","reservedAssistantMessageId":"{ASSISTANT_ID}","reason":"future_reason""#),
    )
    .replace("\"taskRunStreamVersion\":5", "\"taskRunStreamVersion\":6");
    for (case, body) in [
        v5_cancelled,
        v6_failure,
        v6_completed,
        v6_prohibited_cancelled,
        v6_unknown,
    ]
    .into_iter()
    .enumerate()
    {
        let (origin, server) = serve(body).await;
        let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
        let error = client.reconcile_command(text_request()).await.unwrap_err();
        assert_eq!(
            error.kind(),
            runne_runtime_client::RuntimeApiErrorKind::InvalidResponse,
            "case {case}"
        );
        server.await.unwrap();
    }
}
