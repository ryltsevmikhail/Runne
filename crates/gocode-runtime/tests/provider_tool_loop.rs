use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use gocode_provider::{
    CancelDisposition, CancelRequest, DispatchAttemptId, DispatchError, DispatchRequest, ModelRef,
    PrepareError, PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderCallId,
    ProviderCapability, ProviderDispatchClaim, ProviderFinishReason, ProviderFuture, ProviderId,
    ProviderPort, ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId,
    ProviderStreamItem, ProviderTerminalDisposition, ProviderUsage, ReconcileRequest,
    ReconciliationDisposition, ScriptedProvider, StreamCursor, StreamError,
};
use gocode_runtime::provider_tool::{
    ProviderToolJournal, ProviderToolLoop, ProviderToolLoopError, ProviderToolLoopOutcome,
    ProviderToolRecoveryState, ProviderToolRecoveryStatus, ProviderToolTransition, RuntimeToolCall,
    ToolCallHandoffPort, ToolHandoffDisposition,
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Journal {
    cursor: u64,
    text: String,
    usage: Option<ProviderUsage>,
    events: Mutex<Vec<(ProviderStreamId, ProviderStreamEvent)>>,
    transitions: Mutex<Vec<ProviderToolTransition>>,
}

impl ProviderToolJournal for Journal {
    fn recovery_state(
        &self,
        _stream_id: gocode_provider::ProviderStreamId,
    ) -> Result<ProviderToolRecoveryState, ProviderToolLoopError> {
        Ok(ProviderToolRecoveryState::new(
            self.cursor,
            self.text.clone(),
            self.usage,
        ))
    }

    fn append_provider_event(
        &self,
        stream_id: ProviderStreamId,
        event: &ProviderStreamEvent,
    ) -> Result<(), ProviderToolLoopError> {
        self.events.lock().unwrap().push((stream_id, event.clone()));
        Ok(())
    }

    fn append(&self, transition: ProviderToolTransition) -> Result<(), ProviderToolLoopError> {
        self.transitions.lock().unwrap().push(transition);
        Ok(())
    }
}

#[derive(Default)]
struct CrashAfterDurableDeltaJournal {
    recovery: Mutex<(u64, String, Option<ProviderUsage>)>,
    crash_once: AtomicBool,
}

impl ProviderToolJournal for CrashAfterDurableDeltaJournal {
    fn recovery_state(
        &self,
        _stream_id: ProviderStreamId,
    ) -> Result<ProviderToolRecoveryState, ProviderToolLoopError> {
        let (cursor, text, usage) = self.recovery.lock().unwrap().clone();
        Ok(ProviderToolRecoveryState::new(cursor, text, usage))
    }

    fn append_provider_event(
        &self,
        _stream_id: ProviderStreamId,
        event: &ProviderStreamEvent,
    ) -> Result<(), ProviderToolLoopError> {
        let mut recovery = self.recovery.lock().unwrap();
        recovery.0 = event
            .sequence()
            .checked_add(1)
            .ok_or(ProviderToolLoopError::MalformedStream)?;
        match event.kind() {
            ProviderStreamEventKind::TextDelta { text } => recovery.1.push_str(text),
            ProviderStreamEventKind::Usage { usage } => recovery.2 = Some(*usage),
            ProviderStreamEventKind::Started
            | ProviderStreamEventKind::ToolCallRequested { .. }
            | ProviderStreamEventKind::Finished { .. } => {}
        }
        if matches!(event.kind(), ProviderStreamEventKind::TextDelta { .. })
            && !self.crash_once.swap(true, Ordering::SeqCst)
        {
            return Err(ProviderToolLoopError::JournalUnavailable);
        }
        Ok(())
    }

    fn append(&self, _transition: ProviderToolTransition) -> Result<(), ProviderToolLoopError> {
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CrashPoint {
    TerminalEvent,
    ToolEvent,
    ToolResult,
    CancellationIntent,
    CancellationAcknowledged,
    Frozen,
}

struct DurableRecovery {
    cursor: u64,
    text: String,
    usage: Option<ProviderUsage>,
    status: ProviderToolRecoveryStatus,
}

struct CrashRecoveryJournal {
    state: Mutex<DurableRecovery>,
    crash_point: CrashPoint,
    crashed: AtomicBool,
}

impl CrashRecoveryJournal {
    fn new(crash_point: CrashPoint) -> Self {
        Self {
            state: Mutex::new(DurableRecovery {
                cursor: 0,
                text: String::new(),
                usage: None,
                status: ProviderToolRecoveryStatus::Active,
            }),
            crash_point,
            crashed: AtomicBool::new(false),
        }
    }

    fn fail_once(&self, point: CrashPoint) -> Result<(), ProviderToolLoopError> {
        if self.crash_point == point && !self.crashed.swap(true, Ordering::SeqCst) {
            Err(ProviderToolLoopError::JournalUnavailable)
        } else {
            Ok(())
        }
    }
}

impl ProviderToolJournal for CrashRecoveryJournal {
    fn recovery_state(
        &self,
        _stream_id: ProviderStreamId,
    ) -> Result<ProviderToolRecoveryState, ProviderToolLoopError> {
        let state = self.state.lock().unwrap();
        Ok(ProviderToolRecoveryState::from_parts(
            state.cursor,
            state.text.clone(),
            state.usage,
            state.status.clone(),
        ))
    }

    fn append_provider_event(
        &self,
        _stream_id: ProviderStreamId,
        event: &ProviderStreamEvent,
    ) -> Result<(), ProviderToolLoopError> {
        let mut state = self.state.lock().unwrap();
        state.cursor = event
            .sequence()
            .checked_add(1)
            .ok_or(ProviderToolLoopError::MalformedStream)?;
        let crash_point = match event.kind() {
            ProviderStreamEventKind::Started => None,
            ProviderStreamEventKind::TextDelta { text } => {
                state.text.push_str(text);
                None
            }
            ProviderStreamEventKind::Usage { usage } => {
                state.usage = Some(*usage);
                None
            }
            ProviderStreamEventKind::ToolCallRequested {
                call_id,
                tool_name,
                arguments_json,
            } => {
                state.status = ProviderToolRecoveryStatus::ToolCallPending {
                    call: RuntimeToolCall {
                        call_id: call_id.clone(),
                        tool_name: tool_name.clone(),
                        arguments_json: arguments_json.clone(),
                    },
                };
                Some(CrashPoint::ToolEvent)
            }
            ProviderStreamEventKind::Finished {
                disposition,
                reason,
            } => {
                state.status = ProviderToolRecoveryStatus::Terminal {
                    disposition: *disposition,
                    reason: reason.clone(),
                };
                Some(CrashPoint::TerminalEvent)
            }
        };
        drop(state);
        crash_point.map_or(Ok(()), |point| self.fail_once(point))
    }

    fn append(&self, transition: ProviderToolTransition) -> Result<(), ProviderToolLoopError> {
        let (status, crash_point) = match transition {
            ProviderToolTransition::CancellationIntent { .. } => (
                ProviderToolRecoveryStatus::CancellationPending,
                CrashPoint::CancellationIntent,
            ),
            ProviderToolTransition::CancellationAcknowledged { .. } => (
                ProviderToolRecoveryStatus::Cancelled,
                CrashPoint::CancellationAcknowledged,
            ),
            ProviderToolTransition::ToolResult {
                call_id,
                result_digest,
                ..
            } => (
                ProviderToolRecoveryStatus::ToolResultReady {
                    call_id,
                    result_digest,
                },
                CrashPoint::ToolResult,
            ),
            ProviderToolTransition::Frozen { .. } => {
                (ProviderToolRecoveryStatus::Frozen, CrashPoint::Frozen)
            }
        };
        self.state.lock().unwrap().status = status;
        self.fail_once(crash_point)
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
    let claim = ProviderDispatchClaim {
        call_id: prepared.call().call_id(),
        attempt_id: DispatchAttemptId::from_bytes([3; 16]),
        permit_id: [4; 16],
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [6; 32],
        token_reservation_id: [7; 16],
        cost_reservation_id: [8; 16],
        fencing_token: 1,
        provider_idempotency_key: "runtime-provider-tool-loop".to_owned(),
    };
    provider
        .dispatch(DispatchRequest::new(prepared, claim).unwrap())
        .await
        .unwrap()
}

fn handoff(disposition: ToolHandoffDisposition) -> ToolHandoff {
    ToolHandoff {
        disposition,
        calls: Mutex::new(Vec::new()),
    }
}

struct BypassProvider {
    item: ProviderStreamItem,
}

impl ProviderPort for BypassProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        digest_version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, digest_version)
    }

    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!("runtime boundary test supplies a stream") })
    }

    fn next<'a>(
        &'a self,
        _stream: &'a ProviderStreamId,
        _cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        let item = self.item.clone();
        Box::pin(async move { Ok(item) })
    }

    fn cancel(
        &self,
        _request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { Ok(CancelDisposition::Requested) })
    }

    fn reconcile(
        &self,
        _request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
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
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(2, 1, 0, 0).unwrap(),
            },
        ),
        event(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
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
            text: "hello".into(),
            usage: Some(ProviderUsage::new(2, 1, 0, 0).unwrap()),
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
                disposition: ProviderTerminalDisposition::Completed,
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
            text: String::new(),
            usage: None,
        }
    );
}

#[tokio::test]
async fn restart_restores_usage_and_rejects_a_second_usage_event() {
    let provider = BypassProvider {
        item: ProviderStreamItem::from_event(event(
            2,
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(3, 1, 0, 0).unwrap(),
            },
        ))
        .unwrap(),
    };
    let loop_ = ProviderToolLoop::new(
        Journal {
            cursor: 2,
            usage: Some(ProviderUsage::new(2, 1, 0, 0).unwrap()),
            ..Journal::default()
        },
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(
                &provider,
                ProviderStreamId::from_bytes([3; 16]),
                &CancellationToken::new(),
            )
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}

#[tokio::test]
async fn crash_after_event_commit_recovers_exact_text_without_repolling_delta() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "durable".into(),
            },
        ),
        event(
            2,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let loop_ = ProviderToolLoop::new(
        CrashAfterDurableDeltaJournal::default(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Completed {
            text: "durable".into(),
            usage: None,
        }
    );
}

#[tokio::test]
async fn crash_after_terminal_event_commit_recovers_terminal_without_provider_repoll() {
    let provider = provider(vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        ),
    ]);
    let stream = dispatch(&provider).await;
    let loop_ = ProviderToolLoop::new(
        CrashRecoveryJournal::new(CrashPoint::TerminalEvent),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Completed {
            text: String::new(),
            usage: None,
        }
    );
}

#[tokio::test]
async fn crash_after_tool_request_commit_freezes_without_tool_dispatch() {
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
        CrashRecoveryJournal::new(CrashPoint::ToolEvent),
        handoff(ToolHandoffDisposition::Completed {
            result_digest: [9; 32],
        }),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}

#[tokio::test]
async fn crash_after_tool_result_commit_recovers_result_without_second_tool_effect() {
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
        CrashRecoveryJournal::new(CrashPoint::ToolResult),
        handoff(ToolHandoffDisposition::Completed {
            result_digest: [9; 32],
        }),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::ToolResultReady {
            call_id: "call-1".into(),
            result_digest: [9; 32],
        }
    );
}

#[tokio::test]
async fn crash_after_cancellation_intent_recovers_as_uncertain_without_repoll() {
    let provider = provider(vec![event(0, ProviderStreamEventKind::Started)]);
    let stream = dispatch(&provider).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let loop_ = ProviderToolLoop::new(
        CrashRecoveryJournal::new(CrashPoint::CancellationIntent),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_.run(&provider, stream, &cancellation).await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}

#[tokio::test]
async fn crash_after_cancellation_ack_recovers_cancelled_without_second_signal() {
    let provider = provider(vec![event(0, ProviderStreamEventKind::Started)]);
    let stream = dispatch(&provider).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let loop_ = ProviderToolLoop::new(
        CrashRecoveryJournal::new(CrashPoint::CancellationAcknowledged),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_.run(&provider, stream, &cancellation).await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Cancelled
    );
}

#[tokio::test]
async fn crash_after_freeze_commit_recovers_fence_without_provider_repoll() {
    let provider = BypassProvider {
        item: ProviderStreamItem::from_event(event(
            100,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        ))
        .unwrap(),
    };
    let stream = ProviderStreamId::from_bytes([3; 16]);
    let loop_ = ProviderToolLoop::new(
        CrashRecoveryJournal::new(CrashPoint::Frozen),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await,
        Err(ProviderToolLoopError::JournalUnavailable)
    );
    assert_eq!(
        loop_
            .run(&provider, stream, &CancellationToken::new())
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}

#[tokio::test]
async fn runtime_rejects_adapter_event_that_bypasses_stream_grammar() {
    let provider = BypassProvider {
        item: ProviderStreamItem::from_event(event(
            100,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        ))
        .unwrap(),
    };
    let loop_ = ProviderToolLoop::new(
        Journal::default(),
        handoff(ToolHandoffDisposition::Uncertain),
        64,
    )
    .unwrap();

    assert_eq!(
        loop_
            .run(
                &provider,
                ProviderStreamId::from_bytes([3; 16]),
                &CancellationToken::new(),
            )
            .await
            .unwrap(),
        ProviderToolLoopOutcome::Uncertain
    );
}
