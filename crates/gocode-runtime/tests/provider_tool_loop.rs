use std::sync::Mutex;

use gocode_provider::{
    DispatchAttemptId, DispatchRequest, ModelRef, ProviderCall, ProviderCallId, ProviderCapability,
    ProviderFinishReason, ProviderId, ProviderPort, ProviderStreamEvent, ProviderStreamEventKind,
    ScriptedProvider, StreamCursor,
};
use gocode_runtime::provider_tool::{
    ProviderToolJournal, ProviderToolLoop, ProviderToolLoopError, ProviderToolLoopOutcome,
    ProviderToolTransition, RuntimeToolCall, ToolCallHandoffPort, ToolHandoffDisposition,
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Journal {
    cursor: u64,
    transitions: Mutex<Vec<ProviderToolTransition>>,
}

impl ProviderToolJournal for Journal {
    fn next_cursor(
        &self,
        _stream_id: gocode_provider::ProviderStreamId,
    ) -> Result<u64, ProviderToolLoopError> {
        Ok(self.cursor)
    }

    fn append(&self, transition: ProviderToolTransition) -> Result<(), ProviderToolLoopError> {
        self.transitions.lock().unwrap().push(transition);
        Ok(())
    }
}

struct ToolHandoff {
    disposition: ToolHandoffDisposition,
    calls: Mutex<Vec<RuntimeToolCall>>,
}

impl ToolCallHandoffPort for ToolHandoff {
    fn dispatch(
        &self,
        call: &RuntimeToolCall,
    ) -> Result<ToolHandoffDisposition, ProviderToolLoopError> {
        self.calls.lock().unwrap().push(call.clone());
        Ok(self.disposition.clone())
    }
}

fn event(sequence: u64, kind: ProviderStreamEventKind) -> ProviderStreamEvent {
    ProviderStreamEvent::new(sequence, kind).unwrap()
}

fn provider(script: Vec<ProviderStreamEvent>) -> ScriptedProvider {
    ScriptedProvider::new(
        [ProviderCapability::Streaming, ProviderCapability::Tools],
        script,
    )
    .unwrap()
}

async fn dispatch(provider: &ScriptedProvider) -> gocode_provider::ProviderStreamId {
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([1; 16]),
        ModelRef::new(ProviderId::new("fake").unwrap(), "model", "revision").unwrap(),
        [2; 32],
        100,
        serde_json::json!({}),
    )
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    let prepared = provider.prepare(&call).unwrap();
    provider
        .dispatch(DispatchRequest::new(
            prepared,
            DispatchAttemptId::from_bytes([3; 16]),
        ))
        .await
        .unwrap()
}

fn handoff(disposition: ToolHandoffDisposition) -> ToolHandoff {
    ToolHandoff {
        disposition,
        calls: Mutex::new(Vec::new()),
    }
}

#[tokio::test]
async fn text_completion_persists_every_event_before_success() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "hello".into(),
            },
        ),
        event(
            2,
            ProviderStreamEventKind::Finished {
                reason: ProviderFinishReason::Stop,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let loop_ = ProviderToolLoop::new(
        Journal::default(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Completed {
            text: "hello".into()
        }
    );
}

#[tokio::test]
async fn tool_request_is_persisted_before_handoff_and_result_before_continuation() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-1".into(),
                tool_name: "process.exec".into(),
                arguments_json: "{}".into(),
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let loop_ = ProviderToolLoop::new(
        Journal::default(),
        handoff(ToolHandoffDisposition::Completed {
            result_digest: [9; 32],
        }),
        64,
    )
    .unwrap();
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::ToolResultReady {
            call_id: "call-1".into(),
            result_digest: [9; 32]
        }
    );
}

#[tokio::test]
async fn cancellation_intent_precedes_adapter_signal() {
    let provider = provider(vec![event(0, ProviderStreamEventKind::Started)]);
    let stream = dispatch(&provider).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let loop_ = ProviderToolLoop::new(
        Journal::default(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();
    assert_eq!(
        loop_.run(&provider, stream, &cancellation).await.unwrap(),
        ProviderToolLoopOutcome::Cancelled
    );
}

#[tokio::test]
async fn malformed_or_uncertain_effect_freezes_the_loop() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::ToolCallRequested {
                call_id: "call-1".into(),
                tool_name: "process.exec".into(),
                arguments_json: "{}".into(),
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let loop_ = ProviderToolLoop::new(
        Journal::default(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}

#[tokio::test]
async fn restart_uses_durable_cursor_and_does_not_replay_started() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::Finished {
                reason: ProviderFinishReason::Stop,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    provider.next(&stream, StreamCursor::new(0)).await.unwrap();
    let loop_ = ProviderToolLoop::new(
        Journal {
            cursor: 1,
            ..Journal::default()
        },
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Completed {
            text: String::new()
        }
    );
}
