use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use thiserror::Error;

use crate::{
    CancelDisposition, CancelRequest, DispatchAttemptId, DispatchError, DispatchRequest,
    PrepareError, PreparedRequest, ProviderCall, ProviderCapability, ProviderFinishReason,
    ProviderFuture, ProviderPort, ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId,
    ProviderStreamItem, ReconcileRequest, ReconciliationDisposition, StreamCursor, StreamError,
};

#[derive(Debug)]
struct FakeState {
    dispatches: BTreeMap<DispatchAttemptId, (crate::PreparedRequestRef, ProviderStreamId)>,
    cursors: BTreeMap<ProviderStreamId, u64>,
    cancelled: BTreeSet<ProviderStreamId>,
    dispatch_count: usize,
}

/// Invalid deterministic adapter fixture.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScriptedProviderError {
    /// Script sequences were not contiguous from zero.
    #[error(transparent)]
    InvalidSequence(#[from] StreamError),
}

/// Deterministic provider adapter for L0-L2 conformance tests.
#[derive(Debug)]
pub struct ScriptedProvider {
    capabilities: BTreeSet<ProviderCapability>,
    script: Vec<ProviderStreamEvent>,
    state: Mutex<FakeState>,
}

impl ScriptedProvider {
    /// Constructs a deterministic adapter after validating the full script.
    pub fn new(
        capabilities: impl IntoIterator<Item = ProviderCapability>,
        script: Vec<ProviderStreamEvent>,
    ) -> Result<Self, ScriptedProviderError> {
        for (expected, event) in script.iter().enumerate() {
            let expected = expected as u64;
            if event.sequence() != expected {
                return Err(StreamError::InvalidScriptSequence {
                    expected,
                    actual: event.sequence(),
                }
                .into());
            }
        }
        Ok(Self {
            capabilities: capabilities.into_iter().collect(),
            script,
            state: Mutex::new(FakeState {
                dispatches: BTreeMap::new(),
                cursors: BTreeMap::new(),
                cancelled: BTreeSet::new(),
                dispatch_count: 0,
            }),
        })
    }

    /// Returns how many distinct dispatch attempts entered the fake adapter.
    pub fn dispatch_count(&self) -> usize {
        self.state
            .lock()
            .expect("fake mutex poisoned")
            .dispatch_count
    }
}

impl ProviderPort for ScriptedProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        for capability in call.required_capabilities() {
            if !self.capabilities.contains(capability) {
                return Err(PrepareError::UnsupportedCapability(*capability));
            }
        }
        PreparedRequest::from_call(call)
    }

    fn dispatch(
        &self,
        request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("fake mutex poisoned");
            if let Some((existing_ref, stream_id)) = state.dispatches.get(&request.attempt_id()) {
                if *existing_ref == request.prepared().request_ref() {
                    return Ok(*stream_id);
                }
                return Err(DispatchError::AttemptConflict);
            }

            let stream_id = ProviderStreamId::from_bytes(*request.attempt_id().as_bytes());
            state.dispatches.insert(
                request.attempt_id(),
                (request.prepared().request_ref(), stream_id),
            );
            state.cursors.insert(stream_id, 0);
            state.dispatch_count += 1;
            Ok(stream_id)
        })
    }

    fn next<'a>(
        &'a self,
        stream: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("fake mutex poisoned");
            let expected = *state.cursors.get(stream).ok_or(StreamError::NotFound)?;
            if cursor.sequence() != expected {
                return Err(StreamError::SequenceGap {
                    expected,
                    actual: cursor.sequence(),
                });
            }
            let event = self
                .script
                .get(expected as usize)
                .cloned()
                .ok_or(StreamError::Closed)?;
            if let ProviderStreamEventKind::Finished {
                reason: ProviderFinishReason::Unknown { raw },
            } = event.kind()
            {
                return Err(StreamError::UnknownFinishReason { raw: raw.clone() });
            }
            state.cursors.insert(*stream, expected + 1);
            Ok(ProviderStreamItem::new(event))
        })
    }

    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("fake mutex poisoned");
            if !state.cursors.contains_key(&request.stream_id()) {
                return Err(DispatchError::StreamNotFound);
            }
            if state.cancelled.insert(request.stream_id()) {
                Ok(CancelDisposition::Requested)
            } else {
                Ok(CancelDisposition::AlreadyRequested)
            }
        })
    }

    fn reconcile(
        &self,
        request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async move {
            let state = self.state.lock().expect("fake mutex poisoned");
            if state.dispatches.contains_key(&request.attempt_id()) {
                Ok(ReconciliationDisposition::Uncertain)
            } else {
                Ok(ReconciliationDisposition::Absent)
            }
        })
    }
}
