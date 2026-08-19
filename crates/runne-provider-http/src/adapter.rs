use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use runne_provider::{
    CancelDisposition, CancelRequest, DispatchAttemptId, DispatchError, DispatchRequest,
    PrepareError, PreparedRequest, PreparedRequestRef, ProviderFinishReason, ProviderFuture,
    ProviderPort, ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId,
    ProviderStreamItem, ProviderTerminalDisposition, ReconcileRequest, ReconciliationDisposition,
    StreamCursor, StreamError,
};
use serde::Deserialize;

use crate::{
    HttpTransport, HttpTransportRequest, ProfileError, ProviderAdapterProfile, SecretMaterializer,
    TransportError,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureBody {
    events: Vec<FixtureEvent>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FixtureEvent {
    Started,
    TextDelta { text: String },
    Finished { reason: String },
}

enum AttemptState {
    Dispatching(PreparedRequestRef),
    Streaming(PreparedRequestRef, ProviderStreamId),
}

struct State {
    attempts: BTreeMap<DispatchAttemptId, AttemptState>,
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
        let mut state = self.state.lock().map_err(|_| {
            DispatchError::RejectedBeforeEffect(
                runne_provider::ProviderPreEffectRejection::AdapterRejected,
            )
        })?;
        if let Some(attempt) = state.attempts.get(&request.attempt_id()) {
            return match attempt {
                AttemptState::Dispatching(prepared_ref)
                    if *prepared_ref == request.prepared().request_ref() =>
                {
                    Err(DispatchError::MaybeDispatched)
                }
                AttemptState::Streaming(prepared_ref, stream)
                    if *prepared_ref == request.prepared().request_ref() =>
                {
                    Ok(*stream)
                }
                AttemptState::Dispatching(_) | AttemptState::Streaming(_, _) => {
                    Err(DispatchError::AttemptConflict)
                }
            };
        }
        let body = request.prepared().rendered_bytes().to_vec();
        if body.len() > self.profile.max_body_bytes {
            return Err(DispatchError::RejectedBeforeEffect(
                runne_provider::ProviderPreEffectRejection::AdapterRejected,
            ));
        }
        if request.claim().profile_digest != self.profile.profile_digest {
            return Err(DispatchError::RejectedBeforeEffect(
                runne_provider::ProviderPreEffectRejection::ProfileRejected,
            ));
        }
        let authorization = self.secrets.materialize().map_err(|_| {
            DispatchError::RejectedBeforeEffect(
                runne_provider::ProviderPreEffectRejection::CredentialAccessDenied,
            )
        })?;
        state.attempts.insert(
            request.attempt_id(),
            AttemptState::Dispatching(request.prepared().request_ref()),
        );
        let response = match self.transport.send(HttpTransportRequest {
            origin: self.profile.origin.clone(),
            path: self.profile.path.clone(),
            body,
            provider_idempotency_key: request.provider_idempotency_key().to_owned(),
            authorization,
            follow_redirects: false,
            use_ambient_proxy: false,
        }) {
            Ok(response) => response,
            Err(_) => return Err(DispatchError::MaybeDispatched),
        };
        let events = match normalize_response(&self.profile, response) {
            Ok(events) => events,
            Err(_) => return Err(DispatchError::MaybeDispatched),
        };
        let stream = ProviderStreamId::from_bytes(*request.attempt_id().as_bytes());
        state.attempts.insert(
            request.attempt_id(),
            AttemptState::Streaming(request.prepared().request_ref(), stream),
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
        call: &runne_provider::ProviderCall,
    ) -> Result<PreparedRequest, PrepareError> {
        self.profile
            .validate_call(call)
            .map_err(|error| PrepareError::Render(error.to_string()))?;
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &runne_provider::ProviderCall,
        digest_version: runne_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        self.profile
            .validate_call(call)
            .map_err(|error| PrepareError::Render(error.to_string()))?;
        PreparedRequest::from_call_for_digest_version(call, digest_version)
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
        _request: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
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
                FixtureEvent::Finished { reason } => {
                    let (reason, disposition) = match reason.as_str() {
                        "stop" => (
                            ProviderFinishReason::Stop,
                            ProviderTerminalDisposition::Completed,
                        ),
                        "tool_calls" => (
                            ProviderFinishReason::ToolCalls,
                            ProviderTerminalDisposition::RemoteIncomplete,
                        ),
                        "length" => (
                            ProviderFinishReason::Length,
                            ProviderTerminalDisposition::RemoteIncomplete,
                        ),
                        "content_filter" => (
                            ProviderFinishReason::ContentFilter,
                            ProviderTerminalDisposition::RemoteIncomplete,
                        ),
                        "error" => (
                            ProviderFinishReason::Error,
                            ProviderTerminalDisposition::RemoteFailed,
                        ),
                        "cancelled" => (
                            ProviderFinishReason::Cancelled,
                            ProviderTerminalDisposition::CancelledUncertain,
                        ),
                        _ => return Err(TransportError::InvalidResponse),
                    };
                    ProviderStreamEventKind::Finished {
                        disposition,
                        reason,
                    }
                }
            };
            ProviderStreamEvent::new(sequence as u64, kind)
                .map_err(|_| TransportError::InvalidResponse)
        })
        .collect()
}
