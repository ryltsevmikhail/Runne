impl ReplayPendingBaselineResume {
    /// Native-TCB checkpoint capability for sealed local promotion only.
    #[must_use]
    pub const fn baseline_checkpoint_capability(
        &self,
    ) -> &runne_api::AuthenticatedReplayBaselineCheckpointV2 {
        &self.baseline_checkpoint_capability
    }

    /// Current semantic projection accepted by the V18 admission transaction.
    #[must_use]
    pub const fn accepted_promotion(&self) -> &ReplayAcceptedPromotionV2 {
        &self.accepted_promotion
    }

    /// Consumes the pending admission only after local promotion has committed.
    ///
    /// # Errors
    ///
    /// Returns an error if acknowledgement, catch-up completion, or the live
    /// transition is rejected by the authenticated runtime.
    pub async fn activate(mut self) -> Result<ReplayLiveSession, ReplayClientError> {
        let session_id = self
            .session_id
            .as_ref()
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse))?;
        if let Some(cursor) = &self.final_suffix_cursor {
            self.client.acknowledge_replay(session_id, cursor).await?;
        }
        let path = wire::session_value(session_id);
        let complete: CompleteCatchUpResponseWire = self
            .client
            .post_replay_empty(&format!("/v1/replay/{path}/complete-catch-up"))
            .await?;
        if complete.session_state != "catch_up_complete" {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        validate_bounded_lower_hex(&complete.catch_up_proof, MAXIMUM_CURSOR_BYTES)?;
        let live: ContinueLiveResponseWire = self
            .client
            .post_replay_empty(&format!("/v1/replay/{path}/continue-live"))
            .await?;
        if live.session_state != "live" {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        let live_delivery_id = wire::live_id(&live.live_delivery_id)?;
        let validator = self
            .validator
            .take()
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse))?;
        let session_id = self
            .session_id
            .take()
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse))?;
        Ok(ReplayLiveSession {
            client: self.client.clone(),
            scope: self.scope,
            session_id,
            live_delivery_id,
            validator,
            response: None,
            decoder: SseDecoder::default(),
            pending: VecDeque::new(),
            last_delivery_sequence: None,
            terminal_returned: false,
            unacknowledged: None,
        })
    }

    /// Explicitly closes the non-live server session after failed local promotion.
    pub async fn abort(mut self) {
        if let Some(session_id) = self.session_id.take() {
            self.client.close_replay_session(&session_id).await;
        }
    }
}

impl Drop for ReplayPendingBaselineResume {
    fn drop(&mut self) {
        let Some(session_id) = self.session_id.take() else {
            return;
        };
        let client = self.client.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client.close_replay_session(&session_id),
            )
            .await;
        });
    }
}
