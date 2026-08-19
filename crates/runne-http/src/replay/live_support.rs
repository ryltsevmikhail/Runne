fn terminal(code: &'static str) -> SseItem {
    SseItem::Terminal(SseTerminalFrame {
        transport_version: 1,
        code: code.to_owned(),
    })
}

fn try_terminal(sender: &SseSender, code: &'static str) {
    let _ = sender.try_send(terminal(code));
}

fn live_delivery(
    authenticated: &AuthenticatedRuntimeSession,
    service: &ReplayService,
    session: &ReplaySession,
    event: &ReplayEvent,
    delivery_sequence: u64,
) -> Result<SseDelivery, ReplayHttpFailure> {
    if event.aggregate_type != session.aggregate_type
        || event.aggregate_id != session.aggregate_id
        || !matches!(event.sensitivity, 0..=2)
        || event.schema_version != 1
    {
        return Err(replay_invariant_violation());
    }
    let aggregate_type =
        u8::try_from(session.aggregate_type).map_err(|_| replay_invariant_violation())?;
    let cursor = service
        .build_cursor_from_event(
            event,
            &ReplayScope::Aggregate {
                aggregate_type,
                aggregate_id: session.aggregate_id,
            },
        )
        .map_err(|_| replay_invariant_violation())?;
    let replay_cursor = encode_cursor(&cursor)?;
    let canonical_event = serde_json::to_value(wire_event(authenticated, session, event)?)
        .map_err(|_| replay_invariant_violation())?;
    let live_delivery_id = session
        .live_delivery_id
        .as_deref()
        .map(live_delivery_id_wire)
        .transpose()?
        .ok_or_else(replay_invariant_violation)?;
    Ok(SseDelivery {
        transport_version: 1,
        replay_session_id: session_id_hex(&session.session_id),
        live_delivery_id: Some(live_delivery_id),
        delivery_sequence,
        canonical_event,
        replay_cursor,
    })
}

struct LiveDeliveryGuard {
    authenticated: AuthenticatedRuntimeSession,
    service: Arc<ReplayService>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    first_delivery_sequence: u64,
}

impl ReplayDeliveryPrecommitGuard for LiveDeliveryGuard {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError> {
        for (index, event) in events.iter().enumerate() {
            let sequence_offset =
                u64::try_from(index).map_err(|_| ReplayError::BackpressureExceeded)?;
            let delivery_sequence = self
                .first_delivery_sequence
                .checked_add(sequence_offset)
                .ok_or(ReplayError::BackpressureExceeded)?;
            let delivery = live_delivery(
                &self.authenticated,
                self.service.as_ref(),
                session,
                event,
                delivery_sequence,
            )
            .map_err(replay_http_failure_to_delivery_error)?;
            let bytes =
                serde_json::to_vec(&delivery).map_err(|_| replay_delivery_integrity_error())?;
            if bytes.len() > MAX_SSE_FRAME_BYTES {
                return Err(ReplayError::BackpressureExceeded);
            }
            inspect_replay_bytes(self.prohibited_content.as_ref(), &bytes)?;
        }
        Ok(())
    }
}

fn live_delivery_guard(
    state: &ReplayHttpState,
    authenticated: &AuthenticatedRuntimeSession,
    first_delivery_sequence: u64,
) -> Arc<dyn ReplayDeliveryPrecommitGuard> {
    Arc::new(LiveDeliveryGuard {
        authenticated: authenticated.clone(),
        service: Arc::clone(&state.service),
        prohibited_content: Arc::clone(&state.prohibited_content),
        first_delivery_sequence,
    })
}
