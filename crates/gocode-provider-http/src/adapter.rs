use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use gocode_provider::{
    CancelDisposition, CancelRequest, DispatchAttemptId, DispatchError, DispatchRequest,
    PrepareError, PreparedRequest, PreparedRequestRef, ProviderFinishReason, ProviderFuture,
    ProviderPort, ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId,
    ProviderStreamItem, ReconcileRequest, ReconciliationDisposition, StreamCursor, StreamError,
};
use serde::Deserialize;

use crate::{
    HttpTransport, HttpTransportRequest, ProfileError, ProviderAdapterProfile, SecretMaterializer,
    TransportError,
};

#[derive(Deserialize)]
struct FixtureBody {
    events: Vec<FixtureEvent>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FixtureEvent {
    Started,
    TextDelta { text: String },
    Finished { reason: String },
}

struct State {
    attempts: BTreeMap<DispatchAttemptId, (PreparedRequestRef, ProviderStreamId)>,
    streams: BTreeMap<ProviderStreamId, Vec<ProviderStreamEvent>>,
    cursors: BTreeMap<ProviderStreamId, u64>,
    cancelled: BTreeSet<ProviderStreamId>,
}

/// Exact profile-bound HTTP provider adapter.
pub struct HttpProviderAdapter<T, S> {
    profile: ProviderAdapterProfile,
    transport: T,
    secrets: S,
    state: Mutex<State>,
}

impl<T, S> HttpProviderAdapter<T, S>
where
    T: HttpTransport,
    S: SecretMaterializer,
{
    /// Constructs an adapter only from a valid exact profile.
    pub fn new(
        profile: ProviderAdapterProfile,
        transport: T,
        secrets: S,
    ) -> Result<Self, ProfileError> {
        profile.validate()?;
        Ok(Self {
            profile,
            transport,
            secrets,
            state: Mutex::new(State {
                attempts: BTreeMap::new(),
                streams: BTreeMap::new(),
                cursors: BTreeMap::new(),
                cancelled: BTreeSet::new(),
            }),
        })
    }

    fn dispatch_inner(&self, request: DispatchRequest) -> Result<ProviderStreamId, DispatchError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DispatchError::AttemptConflict)?;
        if let Some((prepared_ref, stream)) = state.attempts.get(&request.attempt_id()) {
            if *prepared_ref != request.prepared().request_ref() {
                return Err(DispatchError::AttemptConflict);
            }
            return Ok(*stream);
        }
        let body = serde_json::to_vec(request.prepared().call())
            .map_err(|_| DispatchError::AttemptConflict)?;
        if body.len() > self.profile.max_body_bytes {
            return Err(DispatchError::AttemptConflict);
        }
        let authorization = self
            .secrets
            .materialize()
            .map_err(|_| DispatchError::AttemptConflict)?;
        let response = self
            .transport
            .send(HttpTransportRequest {
                origin: self.profile.origin.clone(),
                path: self.profile.path.clone(),
                body,
                authorization,
                follow_redirects: false,
                use_ambient_proxy: false,
            })
            .map_err(|_| DispatchError::AttemptConflict)?;
        let events = normalize_response(&self.profile, response)
            .map_err(|_| DispatchError::AttemptConflict)?;
        let stream = ProviderStreamId::from_bytes(*request.attempt_id().as_bytes());
        state.attempts.insert(
            request.attempt_id(),
            (request.prepared().request_ref(), stream),
        );
        state.streams.insert(stream, events);
        state.cursors.insert(stream, 0);
        Ok(stream)
    }
}

impl<T, S> ProviderPort for HttpProviderAdapter<T, S>
where
    T: HttpTransport,
    S: SecretMaterializer,
{
    fn prepare(
        &self,
        call: &gocode_provider::ProviderCall,
    ) -> Result<PreparedRequest, PrepareError> {
        self.profile
            .validate_call(call)
            .map_err(|error| PrepareError::Render(error.to_string()))?;
        PreparedRequest::from_call(call)
    }

    fn dispatch(
        &self,
        request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move { self.dispatch_inner(request) })
    }

    fn next<'a>(
        &'a self,
        stream: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_| StreamError::NotFound)?;
            let expected = *state.cursors.get(stream).ok_or(StreamError::NotFound)?;
            if cursor.sequence() != expected {
                return Err(StreamError::SequenceGap {
                    expected,
                    actual: cursor.sequence(),
                });
            }
            let event = state
                .streams
                .get(stream)
                .and_then(|events| events.get(expected as usize))
                .cloned()
                .ok_or(StreamError::Closed)?;
            state.cursors.insert(*stream, expected + 1);
            ProviderStreamItem::from_event(event)
        })
    }

    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DispatchError::StreamNotFound)?;
            if !state.streams.contains_key(&request.stream_id()) {
                return Err(DispatchError::StreamNotFound);
            }
            Ok(if state.cancelled.insert(request.stream_id()) {
                CancelDisposition::Requested
            } else {
                CancelDisposition::AlreadyRequested
            })
        })
    }

    fn reconcile(
        &self,
        request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async move {
            let state = self
                .state
                .lock()
                .map_err(|_| DispatchError::AttemptConflict)?;
            Ok(if state.attempts.contains_key(&request.attempt_id()) {
                ReconciliationDisposition::Uncertain
            } else {
                ReconciliationDisposition::Absent
            })
        })
    }
}

fn normalize_response(
    profile: &ProviderAdapterProfile,
    response: crate::HttpTransportResponse,
) -> Result<Vec<ProviderStreamEvent>, TransportError> {
    if response.origin != profile.origin || response.path != profile.path {
        return Err(TransportError::OriginMismatch);
    }
    if response.body.len() > profile.max_body_bytes {
        return Err(TransportError::BoundExceeded);
    }
    let body: FixtureBody =
        serde_json::from_slice(&response.body).map_err(|_| TransportError::InvalidResponse)?;
    body.events
        .into_iter()
        .enumerate()
        .map(|(sequence, event)| {
            let kind = match event {
                FixtureEvent::Started => ProviderStreamEventKind::Started,
                FixtureEvent::TextDelta { text } => {
                    if text.len() > profile.max_frame_bytes {
                        return Err(TransportError::BoundExceeded);
                    }
                    ProviderStreamEventKind::TextDelta { text }
                }
                FixtureEvent::Finished { reason } => ProviderStreamEventKind::Finished {
                    reason: match reason.as_str() {
                        "stop" => ProviderFinishReason::Stop,
                        "tool_calls" => ProviderFinishReason::ToolCalls,
                        "length" => ProviderFinishReason::Length,
                        "content_filter" => ProviderFinishReason::ContentFilter,
                        "error" => ProviderFinishReason::Error,
                        "cancelled" => ProviderFinishReason::Cancelled,
                        _ => return Err(TransportError::InvalidResponse),
                    },
                },
            };
            ProviderStreamEvent::new(sequence as u64, kind)
                .map_err(|_| TransportError::InvalidResponse)
        })
        .collect()
}
