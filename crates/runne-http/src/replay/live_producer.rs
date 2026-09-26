struct LiveProducer {
    state: ReplayHttpState,
    session_id: [u8; 16],
    principal_id: String,
    authenticated: AuthenticatedRuntimeSession,
    binding: ReplayHttpBinding,
    sender: SseSender,
    _session_permit: ReplayCountPermit,
    _live_permit: ReplayCountPermit,
    _drain_claim: SessionClaim,
}

async fn produce_live_events(
    producer: LiveProducer,
    mut session: runne_application::replay_service::ReplaySession,
    mut events: Vec<ReplayEvent>,
) {
    let LiveProducer {
        state,
        session_id,
        principal_id,
        authenticated,
        binding,
        sender,
        _session_permit,
        _live_permit,
        _drain_claim,
    } = producer;
    let mut delivery_sequence = 1_u64;
    let mut stop = false;

    while !stop && !sender.is_closed() {
        for event in events.drain(..) {
            let delivery = match live_delivery(
                &authenticated,
                state.service.as_ref(),
                &session,
                &event,
                delivery_sequence,
            ) {
                Ok(delivery) => delivery,
                Err(error) => {
                    try_terminal(&sender, error.code);
                    stop = true;
                    break;
                }
            };
            let delivery_bytes = match serde_json::to_vec(&delivery) {
                Ok(bytes) => bytes,
                Err(_) => {
                    try_terminal(&sender, "runtime_invariant_violation");
                    stop = true;
                    break;
                }
            };
            let frame_size = delivery_bytes.len();
            if frame_size > MAX_SSE_FRAME_BYTES {
                try_terminal(&sender, "replay_backpressure");
                stop = true;
                break;
            }
            match sender.try_send(SseItem::Delivery(delivery)) {
                Ok(()) => {
                    delivery_sequence = match delivery_sequence.checked_add(1) {
                        Some(next) => next,
                        None => {
                            try_terminal(&sender, "replay_backpressure");
                            stop = true;
                            break;
                        }
                    };
                }
                Err(SseSendError::Backpressure) => {
                    try_terminal(&sender, "replay_backpressure");
                    stop = true;
                    break;
                }
                Err(SseSendError::Closed) => {
                    stop = true;
                    break;
                }
            }
        }

        if stop || sender.is_closed() {
            break;
        }
        tokio::time::sleep(LIVE_POLL_INTERVAL).await;
        match state
            .service
            .poll_live(
                &session_id,
                &principal_id,
                binding.session_generation,
                &binding.authority_id,
                binding.authorization_epoch,
                live_delivery_guard(&state, &authenticated, delivery_sequence),
            )
            .await
        {
            Ok((next_session, next_events)) => {
                session = next_session;
                events = next_events;
            }
            Err(
                ReplayError::Unauthorized(_)
                | ReplayError::StaleGeneration
                | ReplayError::StreamTerminated
                | ReplayError::SessionNotFound,
            ) => {
                try_terminal(&sender, "replay_session_expired");
                break;
            }
            Err(ReplayError::AuthorizationRevoked) => {
                try_terminal(&sender, "replay_authorization_revoked");
                break;
            }
            Err(ReplayError::SensitivityDenied) => {
                try_terminal(&sender, "replay_sensitivity_denied");
                break;
            }
            Err(ReplayError::ReplayRetentionGap { .. }) => {
                try_terminal(&sender, "replay_retention_gap");
                break;
            }
            Err(ReplayError::Integrity(message)) if message == "unsupported replay schema" => {
                try_terminal(&sender, "replay_unsupported_schema");
                break;
            }
            Err(ReplayError::BackpressureExceeded) => {
                try_terminal(&sender, "replay_backpressure");
                break;
            }
            Err(_) => {
                try_terminal(&sender, "runtime_invariant_violation");
                break;
            }
        }
    }

    let _ = state
        .service
        .close_session(
            &session_id,
            &principal_id,
            binding.session_generation,
            &binding.authority_id,
            binding.authorization_epoch,
        )
        .await;
}
