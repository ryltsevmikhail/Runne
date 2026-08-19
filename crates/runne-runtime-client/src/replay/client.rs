use super::http::read_replay_json;
use super::identity::DeliveryValidator;
use super::validation::validate_bounded_lower_hex;
use super::wire::{
    self, AcknowledgeRequestWire, AcknowledgeResponseWire, CompleteCatchUpResponseWire,
    ContinueLiveResponseWire, OpenSessionRequestWire, OpenSessionResponseWire, ReadPageRequestWire,
    ReadPageResponseWire, parse_http_delivery,
};
use super::{
    AuthenticatedRuntimeClient, CONTENT_TYPE, Digest, MAXIMUM_CURSOR_BYTES,
    MAXIMUM_REPLAY_REQUEST_BYTES, REPLAY_PAGE_LIMIT, ReplayClientError, ReplayClientErrorKind,
    ReplayCursor, ReplayDelivery, ReplayIdentityTracker, ReplayLiveSession,
    ReplayPersistenceBinding, ReplayScope, ReplaySessionId, Serialize, Sha256, SseDecoder,
    VecDeque,
};

impl AuthenticatedRuntimeClient {
    /// Returns a stable persistence binding that excludes daemon instance,
    /// launch generation, session identity, authorization epoch, endpoint,
    /// certificate and session authority.
    #[must_use]
    pub fn replay_persistence_binding(&self) -> ReplayPersistenceBinding {
        let session = self.session_info();
        let mut hasher = Sha256::new();
        hasher.update(b"runne/replay-persistence-binding/v1\0");
        for value in [
            session.authority_id.as_bytes(),
            session.principal_id.as_bytes(),
            session.event_log_lineage_id.as_bytes(),
            session.profile_id.as_bytes(),
            session.schema_hash.as_bytes(),
            session.capability_digest.as_bytes(),
        ] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        ReplayPersistenceBinding {
            digest: format!("{:x}", hasher.finalize()),
        }
    }

    /// Applies and acknowledges bounded catch-up pages, then enters live mode.
    ///
    /// The callback always runs before acknowledgement, including for exact
    /// duplicates. A callback failure is terminal and leaves the cursor
    /// unacknowledged.
    ///
    /// # Errors
    ///
    /// Returns a closed replay failure without advancing past the failing
    /// delivery.
    pub async fn catch_up<F, E>(
        &self,
        scope: ReplayScope,
        from_cursor: Option<&ReplayCursor>,
        apply: F,
    ) -> Result<ReplayLiveSession, ReplayClientError>
    where
        F: FnMut(&ReplayDelivery) -> Result<(), E>,
    {
        self.catch_up_with_identities(scope, from_cursor, ReplayIdentityTracker::new(), apply)
            .await
    }

    /// Catch-up using caller-retained identity history across reconnects.
    ///
    /// # Errors
    ///
    /// Returns a closed replay failure without acknowledging a delivery whose
    /// callback or validation failed.
    pub async fn catch_up_with_identities<F, E>(
        &self,
        scope: ReplayScope,
        from_cursor: Option<&ReplayCursor>,
        identities: ReplayIdentityTracker,
        apply: F,
    ) -> Result<ReplayLiveSession, ReplayClientError>
    where
        F: FnMut(&ReplayDelivery) -> Result<(), E>,
    {
        self.catch_up_internal(scope, from_cursor, identities, apply, |()| {})
            .await
    }

    /// Resumes from one native-stored opaque cursor, committing each delivery
    /// before server acknowledgement and invoking `acknowledged` only after
    /// that acknowledgement succeeds.
    ///
    /// # Errors
    ///
    /// Returns a closed replay failure without acknowledging a delivery whose
    /// validation or local commit failed.
    pub async fn catch_up_from_persisted_cursor<F, A, T, E>(
        &self,
        scope: ReplayScope,
        from_cursor: Option<&str>,
        identities: ReplayIdentityTracker,
        apply: F,
        acknowledged: A,
    ) -> Result<ReplayLiveSession, ReplayClientError>
    where
        F: FnMut(&ReplayDelivery) -> Result<T, E>,
        A: FnMut(T),
    {
        let persisted_cursor = from_cursor
            .map(|value| wire::cursor(value.to_owned()))
            .transpose()?;
        self.catch_up_internal(
            scope,
            persisted_cursor.as_ref(),
            identities,
            apply,
            acknowledged,
        )
        .await
    }

    async fn catch_up_internal<F, A, T, E>(
        &self,
        scope: ReplayScope,
        from_cursor: Option<&ReplayCursor>,
        identities: ReplayIdentityTracker,
        mut apply: F,
        mut acknowledged: A,
    ) -> Result<ReplayLiveSession, ReplayClientError>
    where
        F: FnMut(&ReplayDelivery) -> Result<T, E>,
        A: FnMut(T),
    {
        let request = OpenSessionRequestWire {
            aggregate_type: scope.aggregate_kind.wire_value(),
            aggregate_id: scope.aggregate_id.to_string(),
            from_cursor: from_cursor.map(wire::cursor_value),
        };
        let open: OpenSessionResponseWire = self.post_open_session(&request, scope).await?;
        let session_id = wire::session_id(&open.session_id)?;
        validate_bounded_lower_hex(&open.high_water_ref, MAXIMUM_CURSOR_BYTES)?;
        let mut validator = DeliveryValidator::new(scope, identities);
        let mut events = open.events;
        if events.len() > REPLAY_PAGE_LIMIT {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::ResponseTooLarge,
            ));
        }
        let mut has_more = open.has_more;

        loop {
            if has_more && events.is_empty() {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::InvalidResponse,
                ));
            }
            for value in events {
                let (wire_event, cursor) = parse_http_delivery(value)?;
                let delivery = validator.validate(wire_event, cursor, session_id.clone())?;
                let committed = apply(&delivery)
                    .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::LocalCallback))?;
                self.acknowledge_replay(&session_id, delivery.cursor())
                    .await?;
                acknowledged(committed);
            }
            if !has_more {
                break;
            }
            let path = format!("/v1/replay/{}/read-page", wire::session_value(&session_id));
            let page: ReadPageResponseWire = self
                .post_replay_json(
                    &path,
                    &ReadPageRequestWire {
                        limit: REPLAY_PAGE_LIMIT,
                    },
                )
                .await?;
            if page.events.len() > REPLAY_PAGE_LIMIT {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::ResponseTooLarge,
                ));
            }
            events = page.events;
            has_more = page.has_more;
        }

        let session_path = wire::session_value(&session_id);
        let completed: CompleteCatchUpResponseWire = self
            .post_replay_empty(&format!("/v1/replay/{session_path}/complete-catch-up"))
            .await?;
        if completed.session_state != "catch_up_complete" {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        validate_bounded_lower_hex(&completed.catch_up_proof, MAXIMUM_CURSOR_BYTES)?;

        let live: ContinueLiveResponseWire = self
            .post_replay_empty(&format!("/v1/replay/{session_path}/continue-live"))
            .await?;
        if live.session_state != "live" {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        let live_delivery_id = wire::live_id(&live.live_delivery_id)?;

        Ok(ReplayLiveSession {
            client: self.clone(),
            scope,
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

    pub(super) async fn acknowledge_replay(
        &self,
        session_id: &ReplaySessionId,
        cursor: &ReplayCursor,
    ) -> Result<(), ReplayClientError> {
        let path = format!("/v1/replay/{}/acknowledge", wire::session_value(session_id));
        let response: AcknowledgeResponseWire = self
            .post_replay_json(
                &path,
                &AcknowledgeRequestWire {
                    cursor: wire::cursor_value(cursor),
                },
            )
            .await?;
        if !response.acknowledged {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidResponse,
            ));
        }
        Ok(())
    }

    pub(super) async fn post_replay_json<T, R>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, ReplayClientError>
    where
        T: Serialize + Sync + ?Sized,
        R: serde::de::DeserializeOwned,
    {
        let body = serde_json::to_vec(body)
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::InvalidRequest))?;
        if body.len() > MAXIMUM_REPLAY_REQUEST_BYTES {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidRequest,
            ));
        }
        let request = self
            .authenticated_request(self.http_client().post(self.url(path)))
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        let response = request
            .send()
            .await
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
        read_replay_json(response).await
    }
    pub(super) async fn post_replay_empty<R>(&self, path: &str) -> Result<R, ReplayClientError>
    where
        R: serde::de::DeserializeOwned,
    {
        let request = self
            .authenticated_request(self.http_client().post(self.url(path)))
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
        let response = request
            .send()
            .await
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
        read_replay_json(response).await
    }

    pub(super) async fn close_replay_session(&self, session: &ReplaySessionId) {
        let path = format!("/v1/replay/{}/close", wire::session_value(session));
        let Ok(request) = self.authenticated_request(self.http_client().post(self.url(&path)))
        else {
            return;
        };
        let _ = request.send().await;
    }
}
