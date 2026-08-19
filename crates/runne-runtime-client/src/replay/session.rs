use super::http::{ensure_content_type, map_sse_decode_error, read_replay_error};
use super::identity::DeliveryValidator;
use super::wire::{self, SseDeliveryWire, SseTerminalWire, parse_sse_event};
use super::{
    ACCEPT, AuthenticatedRuntimeClient, LiveDeliveryId, RawSseFrame, ReplayClientError,
    ReplayClientErrorKind, ReplayCursor, ReplayDelivery, ReplayRecoveryDisposition, ReplayScope,
    ReplaySessionId, SSE_SILENCE_TIMEOUT, SseDecoder, VecDeque, fmt,
};

/// Closed terminal SSE code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayTerminalCode {
    SessionExpired,
    AuthorizationRevoked,
    SensitivityDenied,
    RetentionGap,
    UnsupportedSchema,
    Backpressure,
    Integrity,
}

impl ReplayTerminalCode {
    fn parse(value: &str) -> Result<Self, ReplayClientError> {
        match value {
            "replay_session_expired" => Ok(Self::SessionExpired),
            "replay_authorization_revoked" => Ok(Self::AuthorizationRevoked),
            "replay_sensitivity_denied" => Ok(Self::SensitivityDenied),
            "replay_retention_gap" => Ok(Self::RetentionGap),
            "replay_unsupported_schema" => Ok(Self::UnsupportedSchema),
            "replay_backpressure" => Ok(Self::Backpressure),
            "runtime_invariant_violation" => Ok(Self::Integrity),
            _ => Err(ReplayClientError::new(
                ReplayClientErrorKind::SchemaMismatch,
            )),
        }
    }

    #[must_use]
    pub const fn recovery_disposition(self) -> ReplayRecoveryDisposition {
        match self {
            Self::SessionExpired | Self::Backpressure => ReplayRecoveryDisposition::Reconnectable,
            Self::UnsupportedSchema => ReplayRecoveryDisposition::Incompatible,
            // An SSE terminal contains no authenticated baseline witness, so
            // it can never authorize local recovery or resynchronization.
            Self::RetentionGap | Self::Integrity => ReplayRecoveryDisposition::Fatal,
            Self::AuthorizationRevoked | Self::SensitivityDenied => {
                ReplayRecoveryDisposition::Revoked
            }
        }
    }
}

/// Validated terminal replay notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayTerminal {
    code: ReplayTerminalCode,
}

impl ReplayTerminal {
    #[must_use]
    pub const fn code(self) -> ReplayTerminalCode {
        self.code
    }

    #[must_use]
    pub const fn recovery_disposition(self) -> ReplayRecoveryDisposition {
        self.code.recovery_disposition()
    }
}

/// One validated live stream item.
#[derive(Clone, Eq, PartialEq)]
pub enum ReplayStreamEvent {
    Delivery(Box<ReplayDelivery>),
    Terminal(ReplayTerminal),
    Heartbeat,
}

impl fmt::Debug for ReplayStreamEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delivery(delivery) => formatter.debug_tuple("Delivery").field(delivery).finish(),
            Self::Terminal(terminal) => formatter.debug_tuple("Terminal").field(terminal).finish(),
            Self::Heartbeat => formatter.write_str("Heartbeat"),
        }
    }
}

/// Live replay session after explicit catch-up completion proof.
pub struct ReplayLiveSession {
    pub(super) client: AuthenticatedRuntimeClient,
    pub(super) scope: ReplayScope,
    pub(super) session_id: ReplaySessionId,
    pub(super) live_delivery_id: LiveDeliveryId,
    pub(super) validator: DeliveryValidator,
    pub(super) response: Option<reqwest::Response>,
    pub(super) decoder: SseDecoder,
    pub(super) pending: VecDeque<RawSseFrame>,
    pub(super) last_delivery_sequence: Option<u64>,
    pub(super) terminal_returned: bool,
    pub(super) unacknowledged: Option<ReplayCursor>,
}

impl ReplayLiveSession {
    #[must_use]
    pub const fn scope(&self) -> ReplayScope {
        self.scope
    }

    #[must_use]
    pub const fn session_id(&self) -> &ReplaySessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn live_delivery_id(&self) -> &LiveDeliveryId {
        &self.live_delivery_id
    }

    /// Receives the next validated delivery, heartbeat or terminal frame.
    ///
    /// EOF and silence are reconnectable transport failures and are never
    /// interpreted as replay completion.
    ///
    /// # Errors
    ///
    /// Returns a closed replay failure for transport silence/EOF or any
    /// malformed, oversized, mismatched or terminally invalid frame.
    pub async fn next_event(&mut self) -> Result<ReplayStreamEvent, ReplayClientError> {
        self.next_event_once().await
    }

    async fn next_event_once(&mut self) -> Result<ReplayStreamEvent, ReplayClientError> {
        if self.unacknowledged.is_some() {
            return Err(ReplayClientError::new(ReplayClientErrorKind::LocalCallback));
        }
        if self.terminal_returned {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        self.ensure_stream().await?;
        let silence_deadline = tokio::time::Instant::now() + SSE_SILENCE_TIMEOUT;
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return self.decode_stream_frame(frame);
            }
            let response = self
                .response
                .as_mut()
                .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
            let next = match tokio::time::timeout_at(silence_deadline, response.chunk()).await {
                Ok(Ok(next)) => next,
                Ok(Err(_)) => {
                    self.reset_stream();
                    return Err(ReplayClientError::new(ReplayClientErrorKind::Transport));
                }
                Err(_) => {
                    self.reset_stream();
                    return Err(ReplayClientError::new(ReplayClientErrorKind::StreamSilence));
                }
            };
            let Some(chunk) = next else {
                let finished = self.decoder.finish().map_err(map_sse_decode_error);
                self.reset_stream();
                finished?;
                return Err(ReplayClientError::new(ReplayClientErrorKind::Transport));
            };
            let frames = self.decoder.push(&chunk).map_err(map_sse_decode_error)?;
            self.pending.extend(frames);
        }
    }

    fn reset_stream(&mut self) {
        self.response = None;
        self.decoder = SseDecoder::default();
        self.pending.clear();
    }

    /// Acknowledges one delivery after `AppCore` has committed it locally.
    ///
    /// # Errors
    ///
    /// Returns a binding or transport failure without changing local state.
    pub async fn acknowledge(
        &mut self,
        delivery: &ReplayDelivery,
    ) -> Result<(), ReplayClientError> {
        if delivery.session_id != self.session_id {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::BindingMismatch,
            ));
        }
        if self.unacknowledged.as_ref() != Some(delivery.cursor()) {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::EventIdentityConflict,
            ));
        }
        self.client
            .acknowledge_replay(&self.session_id, delivery.cursor())
            .await?;
        self.unacknowledged = None;
        Ok(())
    }

    async fn ensure_stream(&mut self) -> Result<(), ReplayClientError> {
        if self.response.is_some() {
            return Ok(());
        }
        let path = format!(
            "/v1/replay/{}/events",
            wire::session_value(&self.session_id)
        );
        let request = self
            .client
            .authenticated_request(self.client.http_client().get(self.client.url(&path)))
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?
            .header(ACCEPT, "text/event-stream");
        let response = request
            .send()
            .await
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
        if response.status().as_u16() != 200 {
            return Err(read_replay_error(response).await);
        }
        ensure_content_type(&response, "text/event-stream")?;
        self.response = Some(response);
        Ok(())
    }

    pub(super) fn decode_stream_frame(
        &mut self,
        frame: RawSseFrame,
    ) -> Result<ReplayStreamEvent, ReplayClientError> {
        match frame {
            RawSseFrame::Heartbeat => Ok(ReplayStreamEvent::Heartbeat),
            RawSseFrame::Terminal(bytes) => {
                let terminal: SseTerminalWire = serde_json::from_slice(&bytes)
                    .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
                if terminal.transport_version != 1 {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::SchemaMismatch,
                    ));
                }
                let terminal = ReplayTerminal {
                    code: ReplayTerminalCode::parse(&terminal.code)?,
                };
                self.terminal_returned = true;
                Ok(ReplayStreamEvent::Terminal(terminal))
            }
            RawSseFrame::Delivery(bytes) => {
                let wire: SseDeliveryWire = serde_json::from_slice(&bytes)
                    .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
                if wire.transport_version != 1 {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::SchemaMismatch,
                    ));
                }
                if wire::session_id(&wire.replay_session_id)? != self.session_id
                    || wire
                        .live_delivery_id
                        .as_deref()
                        .map(wire::live_id)
                        .transpose()?
                        .as_ref()
                        != Some(&self.live_delivery_id)
                {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::BindingMismatch,
                    ));
                }
                let expected_delivery_sequence = self
                    .last_delivery_sequence
                    .map_or(Some(1), |last| last.checked_add(1));
                if Some(wire.delivery_sequence) != expected_delivery_sequence {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::NonMonotonicSequence,
                    ));
                }
                self.last_delivery_sequence = Some(wire.delivery_sequence);
                let event = parse_sse_event(wire.canonical_event)?;
                let delivery =
                    self.validator
                        .validate(event, wire.replay_cursor, self.session_id.clone())?;
                self.unacknowledged = Some(delivery.cursor().clone());
                Ok(ReplayStreamEvent::Delivery(Box::new(delivery)))
            }
        }
    }
}

include!("session_drop.rs");
