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
    usage_unavailable: bool,
    events: Mutex<Vec<(ProviderStreamId, ProviderStreamEvent)>>,
    transitions: Mutex<Vec<ProviderToolTransition>>,
}

impl ProviderToolJournal for Journal {
    fn recovery_state(
        &self,
        _stream_id: gocode_provider::ProviderStreamId,
    ) -> Result<ProviderToolRecoveryState, ProviderToolLoopError> {
        Ok(ProviderToolRecoveryState::from_parts(
            self.cursor,
            self.text.clone(),
            self.usage,
            self.usage_unavailable,
            ProviderToolRecoveryStatus::Active,
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
            | ProviderStreamEventKind::UsageUnavailable
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
    usage_unavailable: bool,
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
                usage_unavailable: false,
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
            state.usage_unavailable,
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
            ProviderStreamEventKind::UsageUnavailable => {
                state.usage_unavailable = true;
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
