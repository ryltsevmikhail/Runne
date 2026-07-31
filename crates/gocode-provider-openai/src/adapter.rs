use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use gocode_provider::{
    CancelDisposition, CancelRequest, DispatchAttemptId, DispatchError, DispatchRequest,
    PrepareError, PreparedRequest, PreparedRequestRef, ProviderCall, ProviderCallDigestVersion,
    ProviderFuture, ProviderPort, ProviderPreEffectRejection, ProviderStreamEvent,
    ProviderStreamEventKind, ProviderStreamId, ProviderStreamItem, ReconcileRequest,
    ReconciliationDisposition, StreamCursor, StreamError,
};
use thiserror::Error;

use crate::{
    OpenAiCredentialError, OpenAiCredentialMaterializer, OpenAiResponsesTextProfile,
    OpenAiResponsesTextRenderer, OpenAiTransport, OpenAiTransportError, OpenAiTransportPolicy,
    OpenAiTransportRequest, decode_transport_response,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptState {
    Dispatching {
        prepared: PreparedRequestRef,
    },
    Streaming {
        prepared: PreparedRequestRef,
        stream: ProviderStreamId,
    },
    Settled {
        prepared: PreparedRequestRef,
        stream: ProviderStreamId,
    },
    Uncertain {
        prepared: PreparedRequestRef,
        stream: ProviderStreamId,
    },
}

const OPENAI_MAX_RETAINED_ATTEMPTS: usize = 1_024;
const OPENAI_MAX_ACTIVE_ATTEMPTS: usize = 8;

#[derive(Debug, Default)]
struct AdapterState {
    attempts: BTreeMap<DispatchAttemptId, AttemptState>,
    streams: BTreeMap<ProviderStreamId, VecDeque<ProviderStreamEvent>>,
    cursors: BTreeMap<ProviderStreamId, u64>,
}

impl AdapterState {
    fn can_start_new_attempt(&self) -> bool {
        self.attempts.len() < OPENAI_MAX_RETAINED_ATTEMPTS
            && self
                .attempts
                .values()
                .filter(|attempt| {
                    matches!(
                        attempt,
                        AttemptState::Dispatching { .. } | AttemptState::Streaming { .. }
                    )
                })
                .count()
                < OPENAI_MAX_ACTIVE_ATTEMPTS
    }

    fn next_item(
        &mut self,
        stream: &ProviderStreamId,
        cursor: StreamCursor,
    ) -> Result<ProviderStreamItem, StreamError> {
        let expected = *self.cursors.get(stream).ok_or(StreamError::NotFound)?;
        if cursor.sequence() != expected {
            return Err(StreamError::SequenceGap {
                expected,
                actual: cursor.sequence(),
            });
        }
        let (item, terminal) = {
            let events = self.streams.get_mut(stream).ok_or(StreamError::NotFound)?;
            let event = events.front().cloned().ok_or(StreamError::Closed)?;
            if event.sequence() != expected {
                return Err(StreamError::SequenceGap {
                    expected,
                    actual: event.sequence(),
                });
            }
            let terminal = matches!(event.kind(), ProviderStreamEventKind::Finished { .. });
            if terminal && events.len() != 1 {
                return Err(StreamError::EventAfterTerminal);
            }
            let item = ProviderStreamItem::from_event(event)?;
            events.pop_front();
            (item, terminal)
        };
        if terminal {
            self.finish_stream(*stream)?;
        } else {
            self.cursors.insert(
                *stream,
                expected
                    .checked_add(1)
                    .ok_or(StreamError::SequenceOverflow)?,
            );
        }
        Ok(item)
    }

    fn finish_stream(&mut self, stream: ProviderStreamId) -> Result<(), StreamError> {
        let attempt_id = DispatchAttemptId::from_bytes(*stream.as_bytes());
        let prepared = match self.attempts.get(&attempt_id) {
            Some(AttemptState::Streaming {
                prepared,
                stream: existing,
            }) if *existing == stream => *prepared,
            _ => return Err(StreamError::NotFound),
        };
        self.attempts
            .insert(attempt_id, AttemptState::Settled { prepared, stream });
        self.streams.remove(&stream);
        self.cursors.remove(&stream);
        Ok(())
    }

    fn cancel_stream(
        &mut self,
        stream: ProviderStreamId,
    ) -> Result<CancelDisposition, DispatchError> {
        let attempt_id = DispatchAttemptId::from_bytes(*stream.as_bytes());
        let prepared = match self.attempts.get(&attempt_id) {
            Some(AttemptState::Streaming {
                prepared,
                stream: existing,
            }) if *existing == stream => *prepared,
            Some(AttemptState::Uncertain {
                stream: existing, ..
            }) if *existing == stream => return Ok(CancelDisposition::AlreadyRequested),
            _ => return Err(DispatchError::StreamNotFound),
        };
        self.attempts
            .insert(attempt_id, AttemptState::Uncertain { prepared, stream });
        self.streams.remove(&stream);
        self.cursors.remove(&stream);
        Ok(CancelDisposition::Requested)
    }

    #[cfg(test)]
    fn retained_event_count(&self) -> usize {
        self.streams.values().map(VecDeque::len).sum()
    }
}

enum DispatchStart {
    Existing(ProviderStreamId),
    Ready,
}

/// Adapter construction failure before an instance can dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenAiAdapterError {
    /// Immutable transport policy could not be bound to the exact profile.
    #[error("OpenAI adapter profile is invalid")]
    InvalidProfile,
}

/// Exact-profile `OpenAI` Responses text provider adapter.
pub struct OpenAiProviderAdapter<T, C> {
    profile: OpenAiResponsesTextProfile,
    renderer: OpenAiResponsesTextRenderer,
    policy: OpenAiTransportPolicy,
    transport: T,
    credential: C,
    state: Mutex<AdapterState>,
}

impl<T, C> OpenAiProviderAdapter<T, C>
where
    T: OpenAiTransport,
    C: OpenAiCredentialMaterializer,
{
    /// Constructs an adapter pinned to one immutable profile and transport.
    ///
    /// # Errors
    ///
    /// Rejects any profile that cannot produce the exact HTTPS policy.
    pub fn new(
        profile: OpenAiResponsesTextProfile,
        transport: T,
        credential: C,
    ) -> Result<Self, OpenAiAdapterError> {
        let policy = OpenAiTransportPolicy::for_profile(&profile)
            .map_err(|_| OpenAiAdapterError::InvalidProfile)?;
        Ok(Self {
            renderer: OpenAiResponsesTextRenderer::new(profile.clone()),
            profile,
            policy,
            transport,
            credential,
            state: Mutex::new(AdapterState::default()),
        })
    }

    fn prepare_exact(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        self.renderer
            .prepare(call)
            .map_err(|error| PrepareError::Render(error.to_string()))
    }

    fn start_dispatch(&self, request: &DispatchRequest) -> Result<DispatchStart, DispatchError> {
        let prepared_ref = request.prepared().request_ref();
        let mut state = self.state.lock().map_err(|_| {
            DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
        })?;
        if let Some(existing) = state.attempts.get(&request.attempt_id()) {
            return match existing {
                AttemptState::Dispatching { prepared } if *prepared == prepared_ref => {
                    Err(DispatchError::MaybeDispatched)
                }
                AttemptState::Streaming { prepared, stream }
                | AttemptState::Settled { prepared, stream }
                    if *prepared == prepared_ref =>
                {
                    Ok(DispatchStart::Existing(*stream))
                }
                AttemptState::Uncertain { prepared, .. } if *prepared == prepared_ref => {
                    Err(DispatchError::MaybeDispatched)
                }
                AttemptState::Dispatching { .. }
                | AttemptState::Streaming { .. }
                | AttemptState::Settled { .. }
                | AttemptState::Uncertain { .. } => Err(DispatchError::AttemptConflict),
            };
        }
        if request.claim().profile_digest != self.profile.profile_digest()
            || request.prepared().rendered_bytes().len() > self.profile.max_request_bytes()
        {
            return Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::ProfileRejected,
            ));
        }
        if !state.can_start_new_attempt() {
            return Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::AdapterRejected,
            ));
        }
        state.attempts.insert(
            request.attempt_id(),
            AttemptState::Dispatching {
                prepared: prepared_ref,
            },
        );
        drop(state);
        Ok(DispatchStart::Ready)
    }

    async fn dispatch_inner(
        &self,
        request: DispatchRequest,
    ) -> Result<ProviderStreamId, DispatchError> {
        let attempt_id = request.attempt_id();
        let prepared_ref = request.prepared().request_ref();
        match self.start_dispatch(&request)? {
            DispatchStart::Existing(stream) => return Ok(stream),
            DispatchStart::Ready => {}
        }
        let credential = match self.credential.materialize().await {
            Ok(credential) if !credential.is_empty() => credential,
            Ok(_) => {
                self.clear_pre_effect_attempt(attempt_id, prepared_ref);
                return Err(DispatchError::RejectedBeforeEffect(
                    ProviderPreEffectRejection::CredentialUnavailable,
                ));
            }
            Err(error) => {
                self.clear_pre_effect_attempt(attempt_id, prepared_ref);
                return Err(map_credential_error(error));
            }
        };
        let transport_request = match OpenAiTransportRequest::new(
            &self.policy,
            request.provider_idempotency_key().to_owned(),
            request.prepared().rendered_bytes().to_vec(),
            credential,
        ) {
            Ok(request) => request,
            Err(error) => {
                self.clear_pre_effect_attempt(attempt_id, prepared_ref);
                return Err(map_pre_effect_transport_error(error));
            }
        };
        let Ok(response) = self.transport.send(transport_request).await else {
            return Err(self.mark_dispatch_uncertain(attempt_id, prepared_ref));
        };
        let Ok(events) = decode_transport_response(&response) else {
            return Err(self.mark_dispatch_uncertain(attempt_id, prepared_ref));
        };
        let stream = ProviderStreamId::from_bytes(*attempt_id.as_bytes());
        let mut state = self
            .state
            .lock()
            .map_err(|_| DispatchError::MaybeDispatched)?;
        match state.attempts.get(&attempt_id) {
            Some(AttemptState::Dispatching { prepared }) if *prepared == prepared_ref => {}
            Some(AttemptState::Streaming {
                prepared,
                stream: existing,
            }) if *prepared == prepared_ref => return Ok(*existing),
            Some(
                AttemptState::Dispatching { .. }
                | AttemptState::Streaming { .. }
                | AttemptState::Settled { .. }
                | AttemptState::Uncertain { .. },
            ) => {
                return Err(DispatchError::AttemptConflict);
            }
            None => return Err(DispatchError::MaybeDispatched),
        }
        state.attempts.insert(
            attempt_id,
            AttemptState::Streaming {
                prepared: prepared_ref,
                stream,
            },
        );
        state.cursors.insert(stream, 0);
        state.streams.insert(stream, events.into());
        drop(state);
        Ok(stream)
    }

    fn mark_dispatch_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        prepared_ref: PreparedRequestRef,
    ) -> DispatchError {
        if let Ok(mut state) = self.state.lock()
            && matches!(
                state.attempts.get(&attempt_id),
                Some(AttemptState::Dispatching { prepared }) if *prepared == prepared_ref
            )
        {
            state.attempts.insert(
                attempt_id,
                AttemptState::Uncertain {
                    prepared: prepared_ref,
                    stream: ProviderStreamId::from_bytes(*attempt_id.as_bytes()),
                },
            );
        }
        DispatchError::MaybeDispatched
    }

    fn clear_pre_effect_attempt(
        &self,
        attempt_id: DispatchAttemptId,
        prepared_ref: PreparedRequestRef,
    ) {
        if let Ok(mut state) = self.state.lock()
            && matches!(
                state.attempts.get(&attempt_id),
                Some(AttemptState::Dispatching { prepared }) if *prepared == prepared_ref
            )
        {
            state.attempts.remove(&attempt_id);
        }
    }
}

impl<T, C> ProviderPort for OpenAiProviderAdapter<T, C>
where
    T: OpenAiTransport,
    C: OpenAiCredentialMaterializer,
{
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        self.prepare_exact(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        digest_version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        if digest_version != ProviderCallDigestVersion::V2 {
            return Err(PrepareError::UnsupportedDigestVersion(digest_version));
        }
        self.prepare_exact(call)
    }

    fn dispatch(
        &self,
        request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move { self.dispatch_inner(request).await })
    }

    fn next<'a>(
        &'a self,
        stream: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_| StreamError::NotFound)?;
            state.next_item(stream, cursor)
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
            state.cancel_stream(request.stream_id())
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
                .map_err(|_| DispatchError::MaybeDispatched)?;
            Ok(match state.attempts.get(&request.attempt_id()) {
                Some(AttemptState::Streaming { .. } | AttemptState::Settled { .. }) => {
                    ReconciliationDisposition::Settled
                }
                Some(AttemptState::Dispatching { .. } | AttemptState::Uncertain { .. }) | None => {
                    ReconciliationDisposition::Uncertain
                }
            })
        })
    }
}

const fn map_credential_error(error: OpenAiCredentialError) -> DispatchError {
    let rejection = match error {
        OpenAiCredentialError::Missing => ProviderPreEffectRejection::CredentialUnavailable,
        OpenAiCredentialError::AccessDenied => ProviderPreEffectRejection::CredentialAccessDenied,
    };
    DispatchError::RejectedBeforeEffect(rejection)
}

const fn map_pre_effect_transport_error(_error: OpenAiTransportError) -> DispatchError {
    DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use gocode_provider::{
        ModelRef, ProviderCallId, ProviderFinishReason, ProviderId, ProviderStreamEventKind,
        ProviderTerminalDisposition,
    };

    use super::*;
    use crate::OPENAI_MAX_SSE_EVENTS;

    fn prepared_ref(seed: u8) -> PreparedRequestRef {
        let call = ProviderCall::new(
            ProviderCallId::from_bytes([seed; 16]),
            ModelRef::new(
                ProviderId::new("fixture-provider").unwrap(),
                "fixture-model",
                "2026-07-31",
            )
            .unwrap(),
            [seed; 32],
            1,
            serde_json::Value::Null,
        )
        .unwrap();
        PreparedRequest::from_call(&call).unwrap().request_ref()
    }

    fn maximum_events() -> VecDeque<ProviderStreamEvent> {
        let mut events = VecDeque::with_capacity(OPENAI_MAX_SSE_EVENTS);
        events.push_back(ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap());
        for sequence in 1..u64::try_from(OPENAI_MAX_SSE_EVENTS - 1).unwrap() {
            events.push_back(
                ProviderStreamEvent::new(
                    sequence,
                    ProviderStreamEventKind::TextDelta {
                        text: "x".to_owned(),
                    },
                )
                .unwrap(),
            );
        }
        events.push_back(
            ProviderStreamEvent::new(
                u64::try_from(OPENAI_MAX_SSE_EVENTS - 1).unwrap(),
                ProviderStreamEventKind::Finished {
                    disposition: ProviderTerminalDisposition::Completed,
                    reason: ProviderFinishReason::Stop,
                },
            )
            .unwrap(),
        );
        events
    }

    #[test]
    fn repeated_maximum_streams_release_payload_and_keep_only_bounded_tombstones() {
        let mut state = AdapterState::default();
        for seed in [1_u8, 2] {
            let attempt = DispatchAttemptId::from_bytes([seed; 16]);
            let stream = ProviderStreamId::from_bytes([seed; 16]);
            let prepared = prepared_ref(seed);
            state
                .attempts
                .insert(attempt, AttemptState::Streaming { prepared, stream });
            state.cursors.insert(stream, 0);
            state.streams.insert(stream, maximum_events());

            for sequence in 0..u64::try_from(OPENAI_MAX_SSE_EVENTS).unwrap() {
                state
                    .next_item(&stream, StreamCursor::new(sequence))
                    .unwrap();
            }
            assert_eq!(state.retained_event_count(), 0);
            assert!(state.streams.is_empty());
            assert!(state.cursors.is_empty());
            assert!(matches!(
                state.attempts.get(&attempt),
                Some(AttemptState::Settled {
                    prepared: retained,
                    stream: retained_stream,
                }) if *retained == prepared && *retained_stream == stream
            ));
        }
        assert_eq!(state.attempts.len(), 2);
        assert!(state.can_start_new_attempt());
    }

    #[test]
    fn cancellation_releases_payload_and_retains_idempotent_uncertain_tombstone() {
        let mut state = AdapterState::default();
        let attempt = DispatchAttemptId::from_bytes([3; 16]);
        let stream = ProviderStreamId::from_bytes([3; 16]);
        state.attempts.insert(
            attempt,
            AttemptState::Streaming {
                prepared: prepared_ref(3),
                stream,
            },
        );
        state.cursors.insert(stream, 0);
        state.streams.insert(stream, maximum_events());

        assert_eq!(
            state.cancel_stream(stream).unwrap(),
            CancelDisposition::Requested
        );
        assert_eq!(
            state.cancel_stream(stream).unwrap(),
            CancelDisposition::AlreadyRequested
        );
        assert_eq!(state.retained_event_count(), 0);
        assert!(state.streams.is_empty());
        assert!(state.cursors.is_empty());
        assert!(matches!(
            state.attempts.get(&attempt),
            Some(AttemptState::Uncertain { .. })
        ));
    }

    #[test]
    fn active_stream_and_full_tombstone_capacity_reject_new_attempts() {
        let mut active = AdapterState::default();
        for seed in 4..u8::try_from(4 + OPENAI_MAX_ACTIVE_ATTEMPTS).unwrap() {
            assert!(active.can_start_new_attempt());
            active.attempts.insert(
                DispatchAttemptId::from_bytes([seed; 16]),
                AttemptState::Dispatching {
                    prepared: prepared_ref(seed),
                },
            );
        }
        assert!(!active.can_start_new_attempt());

        let mut full = AdapterState::default();
        for index in 0..OPENAI_MAX_RETAINED_ATTEMPTS {
            let bytes = u128::try_from(index + 1).unwrap().to_be_bytes();
            full.attempts.insert(
                DispatchAttemptId::from_bytes(bytes),
                AttemptState::Settled {
                    prepared: prepared_ref(u8::try_from((index % 254) + 1).unwrap()),
                    stream: ProviderStreamId::from_bytes(bytes),
                },
            );
        }
        assert!(!full.can_start_new_attempt());
    }
}
