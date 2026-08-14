use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::body::{Body, to_bytes};
use gocode_api::{
    AuthoritativeCommandOutcome, AuthoritativeTextGenerationOutcome, CanonicalConversationMessage,
    CanonicalMessageRole, CommandReconciliationContext, CommandReconciliationDisposition,
    CommandReconciliationHostError, CommandReconciliationHostPort, CommandReconciliationWitness,
    ConversationTextResult, NonNegativeUnixMillis, ProjectCommandAck,
};
use gocode_http::{
    admission::AdmissionState,
    command_reconciliation::CommandReconciliationHttpState,
    health::{HealthState, RecoveryState},
    router::create_router_with_command_reconciliation,
};
use http::{Request, StatusCode};
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xA5; 32];
const CONVERSATION: &str = "018f2e3a-7000-7000-8000-000000000303";
const TASK_RUN: &str = "018f2e3a-7000-7000-8000-000000000304";
const ATTEMPT: &str = "018f2e3a-7000-7000-8000-000000000305";
const USER: &str = "018f2e3a-7000-7000-8000-000000000306";
const ASSISTANT: &str = "018f2e3a-7000-7000-8000-000000000307";

#[derive(Clone)]
struct Host(Arc<AtomicUsize>);
impl CommandReconciliationHostPort for Host {
    async fn reconcile_command(
        &self,
        _: CommandReconciliationContext,
        _: CommandReconciliationWitness,
    ) -> Result<CommandReconciliationDisposition, CommandReconciliationHostError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(CommandReconciliationDisposition::not_committed_retryable())
    }
}

#[derive(Clone)]
struct DurableHost;
impl CommandReconciliationHostPort for DurableHost {
    async fn reconcile_command(
        &self,
        _: CommandReconciliationContext,
        witness: CommandReconciliationWitness,
    ) -> Result<CommandReconciliationDisposition, CommandReconciliationHostError> {
        CommandReconciliationDisposition::durably_recorded(
            &witness,
            AuthoritativeCommandOutcome::project_archived(ProjectCommandAck {
                project_id: "018f2e3a-7000-7000-8000-000000000302".parse().unwrap(),
                new_version: 2,
            }),
        )
    }
}

#[derive(Clone)]
struct TextHost(AuthoritativeCommandOutcome);
impl CommandReconciliationHostPort for TextHost {
    async fn reconcile_command(
        &self,
        _: CommandReconciliationContext,
        witness: CommandReconciliationWitness,
    ) -> Result<CommandReconciliationDisposition, CommandReconciliationHostError> {
        CommandReconciliationDisposition::durably_recorded(&witness, self.0.clone())
    }
}
fn message(id: &str, role: CanonicalMessageRole, text: &str) -> CanonicalConversationMessage {
    CanonicalConversationMessage {
        message_id: id.parse().unwrap(),
        role,
        taskrun_id: TASK_RUN.parse().unwrap(),
        attempt_id: ATTEMPT.parse().unwrap(),
        text: text.into(),
        committed_at: NonNegativeUnixMillis::new(1).unwrap(),
    }
}
#[derive(Clone, Copy)]
enum TextTerminal {
    Completed,
    Rejected,
    ProhibitedInputRejected,
}

fn text_outcome(terminal: TextTerminal) -> AuthoritativeCommandOutcome {
    let rejection = || {
        (
            CONVERSATION.parse().unwrap(),
            TASK_RUN.parse().unwrap(),
            ATTEMPT.parse().unwrap(),
            message(USER, CanonicalMessageRole::User, "hello"),
            ASSISTANT.parse().unwrap(),
        )
    };
    let text = match terminal {
        TextTerminal::Rejected => {
            let (conversation_id, taskrun_id, attempt_id, user_message, reserved) = rejection();
            AuthoritativeTextGenerationOutcome::Rejected {
                conversation_id,
                taskrun_id,
                attempt_id,
                conversation_stream_version: 3,
                taskrun_stream_version: 5,
                user_message,
                reserved_assistant_message_id: reserved,
                reason:
                    gocode_domain::conversation::GenerationFailureReason::ProviderOutputRejected,
            }
        }
        TextTerminal::ProhibitedInputRejected => {
            let (conversation_id, taskrun_id, attempt_id, user_message, reserved) = rejection();
            AuthoritativeTextGenerationOutcome::ProhibitedInputRejected {
                conversation_id,
                taskrun_id,
                attempt_id,
                conversation_stream_version: 3,
                taskrun_stream_version: 5,
                user_message,
                reserved_assistant_message_id: reserved,
                reason:
                    gocode_domain::conversation::GenerationFailureReason::ProviderOutputRejected,
            }
        }
        TextTerminal::Completed => {
            AuthoritativeTextGenerationOutcome::Completed(ConversationTextResult {
                conversation_id: CONVERSATION.parse().unwrap(),
                taskrun_id: TASK_RUN.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                conversation_stream_version: 3,
                taskrun_stream_version: 5,
                user_message: message(USER, CanonicalMessageRole::User, "hello"),
                assistant_message: message(ASSISTANT, CanonicalMessageRole::Assistant, "answer"),
            })
        }
    };
    AuthoritativeCommandOutcome::conversation_text(text)
}

fn app(calls: Arc<AtomicUsize>) -> axum::Router {
    create_router_with_command_reconciliation(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        CommandReconciliationHttpState::new(Host(calls)),
    )
}

fn authorized(request: http::request::Builder) -> http::request::Builder {
    request.header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
}

#[tokio::test]
async fn reconciliation_authenticates_before_parsing_and_returns_no_store_observation() {
    let calls = Arc::new(AtomicUsize::new(0));
    let malformed = Request::builder()
        .method("POST")
        .uri("/v1/commands/reconcile")
        .body(Body::from(r#"{"unknown":true}"#))
        .unwrap();
    let response = app(calls.clone()).oneshot(malformed).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    let request = authorized(Request::builder().method("POST").uri("/v1/commands/reconcile"))
        .header("x-command-id", "018f2e3a-7000-7000-8000-000000000301")
        .header("idempotency-key", "reconcile-test")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"operation":"archive_project","projectId":"018f2e3a-7000-7000-8000-000000000302","expectedVersion":1}"#))
        .unwrap();
    let response = app(calls.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"disposition":"not_committed_retryable"}"#
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn durable_receipt_serializes_as_typed_http_200_outcome() {
    let request = authorized(Request::builder().method("POST").uri("/v1/commands/reconcile"))
        .header("x-command-id", "018f2e3a-7000-7000-8000-000000000301").header("idempotency-key", "reconcile-test").header("content-type", "application/json")
        .body(Body::from(r#"{"operation":"archive_project","projectId":"018f2e3a-7000-7000-8000-000000000302","expectedVersion":1}"#)).unwrap();
    let response = create_router_with_command_reconciliation(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        CommandReconciliationHttpState::new(DurableHost),
    )
    .oneshot(request)
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"disposition":"durably_recorded","outcome":{"operation":"archive_project","projectId":"018f2e3a-7000-7000-8000-000000000302","newVersion":2}}"#
    );
}

#[tokio::test]
async fn text_terminal_receipts_serialize_completed_and_rejected_as_http_200() {
    let completed = format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"generate_conversation_text","terminal":"completed","conversationId":"{CONVERSATION}","taskRunId":"{TASK_RUN}","attemptId":"{ATTEMPT}","conversationStreamVersion":3,"taskRunStreamVersion":5,"userMessage":{{"messageId":"{USER}","role":"user","taskRunId":"{TASK_RUN}","attemptId":"{ATTEMPT}","text":"hello","committedAt":1}},"assistantMessage":{{"messageId":"{ASSISTANT}","role":"assistant","taskRunId":"{TASK_RUN}","attemptId":"{ATTEMPT}","text":"answer","committedAt":1}}}}}}"#
    );
    let rejected = format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"generate_conversation_text","terminal":"rejected","conversationId":"{CONVERSATION}","taskRunId":"{TASK_RUN}","attemptId":"{ATTEMPT}","conversationStreamVersion":3,"taskRunStreamVersion":5,"userMessage":{{"messageId":"{USER}","role":"user","taskRunId":"{TASK_RUN}","attemptId":"{ATTEMPT}","text":"hello","committedAt":1}},"reservedAssistantMessageId":"{ASSISTANT}","reason":"provider_output_rejected"}}}}"#
    );
    let prohibited = format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"generate_conversation_text","terminal":"prohibited_input_rejected","conversationId":"{CONVERSATION}","taskRunId":"{TASK_RUN}","attemptId":"{ATTEMPT}","conversationStreamVersion":3,"taskRunStreamVersion":5,"userMessage":{{"messageId":"{USER}","role":"user","taskRunId":"{TASK_RUN}","attemptId":"{ATTEMPT}","text":"hello","committedAt":1}},"reservedAssistantMessageId":"{ASSISTANT}","reason":"provider_output_rejected"}}}}"#
    );
    for (outcome, expected) in [
        (text_outcome(TextTerminal::Completed), completed),
        (text_outcome(TextTerminal::Rejected), rejected),
        (
            text_outcome(TextTerminal::ProhibitedInputRejected),
            prohibited,
        ),
    ] {
        let request = authorized(Request::builder().method("POST").uri("/v1/commands/reconcile"))
            .header("x-command-id", "018f2e3a-7000-7000-8000-000000000301").header("idempotency-key", "reconcile-test").header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"operation":"generate_conversation_text","conversationId":"{CONVERSATION}","expectedVersion":1,"text":"hello"}}"#))).unwrap();
        let response = create_router_with_command_reconciliation(
            TOKEN,
            HealthState {
                recovery_state: RecoveryState::Ready,
            },
            AdmissionState::new(RecoveryState::Ready),
            CommandReconciliationHttpState::new(TextHost(outcome)),
        )
        .oneshot(request)
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(
            to_bytes(response.into_body(), 4096).await.unwrap(),
            expected
        );
    }
}
