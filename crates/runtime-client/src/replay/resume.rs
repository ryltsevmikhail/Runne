use super::identity::DeliveryValidator;
use super::validation::validate_bounded_lower_hex;
use super::wire::{
    self, CompleteCatchUpResponseWire, ContinueLiveResponseWire, ReadPageRequestWire,
    ReadPageResponseWire, ResumeFromBaselineResponseWire, parse_http_delivery,
};
use super::{
    AuthenticatedRuntimeClient, CONTENT_TYPE, MAXIMUM_CURSOR_BYTES, ParsedAcceptedPromotionV2,
    REPLAY_PAGE_LIMIT, ReplayAcceptedPromotionV2, ReplayClientError, ReplayClientErrorKind,
    ReplayIdentityTracker, ReplayLiveSession, ReplayRetentionBaselineV2, ReplayScope,
    ReplaySessionId, SseDecoder, VecDeque,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;

/// Opaque, non-live resume admission retained until local promotion commits.
pub struct ReplayPendingBaselineResume {
    client: AuthenticatedRuntimeClient,
    scope: ReplayScope,
    session_id: Option<ReplaySessionId>,
    validator: Option<DeliveryValidator>,
    final_suffix_cursor: Option<super::ReplayCursor>,
    baseline_checkpoint_capability: gocode_api::AuthenticatedReplayBaselineCheckpointV2,
    accepted_promotion: ReplayAcceptedPromotionV2,
}

struct ResumeAdmissionAbort {
    client: AuthenticatedRuntimeClient,
    session_id: Option<ReplaySessionId>,
}

impl ResumeAdmissionAbort {
    const fn new(client: AuthenticatedRuntimeClient, session_id: ReplaySessionId) -> Self {
        Self {
            client,
            session_id: Some(session_id),
        }
    }

    const fn session_id(&self) -> &ReplaySessionId {
        self.session_id.as_ref().expect("admission is still owned")
    }

    fn disarm(mut self) -> ReplaySessionId {
        self.session_id.take().expect("admission is still owned")
    }
}

impl Drop for ResumeAdmissionAbort {
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

impl AuthenticatedRuntimeClient {
    /// Begins V2 recovery without acknowledging its suffix or entering live mode.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the authenticated baseline, server response,
    /// suffix, or native persistence callbacks cannot be validated.
    pub async fn begin_resume_from_retention_baseline_v2<B, A, E>(
        &self,
        scope: ReplayScope,
        baseline: &ReplayRetentionBaselineV2,
        accept_baseline: B,
        mut apply_suffix: A,
    ) -> Result<ReplayPendingBaselineResume, ReplayClientError>
    where
        B: FnOnce(
            &gocode_api::AuthenticatedReplayBaselineCheckpointV2,
            &ReplayRetentionBaselineV2,
        ) -> Result<(), E>,
        A: FnMut(&super::ReplayDelivery, bool) -> Result<(), E>,
    {
        let wire = baseline
            .resume_wire(scope)
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::InvalidRequest))?;
        let response = self.post_resume_wire(&wire).await?;
        let session_id = wire::session_id(&response.session_id)?;
        let admission = ResumeAdmissionAbort::new(self.clone(), session_id);
        validate_bounded_lower_hex(&response.high_water_ref, MAXIMUM_CURSOR_BYTES)?;
        wire::cursor(response.baseline_checkpoint.clone())?;
        let accepted = ParsedAcceptedPromotionV2::decode(response.accepted_promotion)?;
        let checkpoint_capability = self
            .replay_authority()
            .replay_baseline_v2_authenticator()
            .map_err(|()| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse))?
            .authenticate_resume_checkpoint_v2(
                baseline.authenticated_capability(),
                parse_baseline_checkpoint(&response.baseline_checkpoint, baseline)?,
            )
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::InvalidResponse))?;
        let mut validator = DeliveryValidator::from_retained_baseline(
            scope,
            ReplayIdentityTracker::new(),
            baseline.sequence(),
        )?;
        if accept_baseline(&checkpoint_capability, baseline).is_err() {
            return Err(ReplayClientError::new(ReplayClientErrorKind::LocalCallback));
        }
        let suffix = Self::apply_unacknowledged_suffix(
            self,
            admission.session_id(),
            &mut validator,
            response.events,
            response.has_more,
            &mut apply_suffix,
        )
        .await?;
        let final_suffix_cursor = suffix.cursor.clone();
        let accepted = accepted.authenticate(self.replay_authority(), baseline, suffix)?;
        let session_id = admission.disarm();
        Ok(ReplayPendingBaselineResume {
            client: self.clone(),
            scope,
            session_id: Some(session_id),
            validator: Some(validator),
            final_suffix_cursor,
            baseline_checkpoint_capability: checkpoint_capability,
            accepted_promotion: accepted,
        })
    }

    async fn apply_unacknowledged_suffix<A, E>(
        &self,
        session_id: &ReplaySessionId,
        validator: &mut DeliveryValidator,
        mut events: Vec<serde_json::Value>,
        mut has_more: bool,
        apply: &mut A,
    ) -> Result<AppliedSuffix, ReplayClientError>
    where
        A: FnMut(&super::ReplayDelivery, bool) -> Result<(), E>,
    {
        let mut last = None;
        let mut last_event = None;
        loop {
            if events.len() > REPLAY_PAGE_LIMIT || (has_more && events.is_empty()) {
                return Err(ReplayClientError::new(
                    ReplayClientErrorKind::InvalidResponse,
                ));
            }
            let event_count = events.len();
            for (index, value) in events.into_iter().enumerate() {
                let (event, cursor) = parse_http_delivery(value)?;
                let delivery = validator.validate(event, cursor, session_id.clone())?;
                let final_suffix = !has_more && index + 1 == event_count;
                apply(&delivery, final_suffix)
                    .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::LocalCallback))?;
                last = Some(delivery.cursor().clone());
                last_event = Some((
                    uuid::Uuid::parse_str(&delivery.event_id().to_string())
                        .map_err(|_| {
                            ReplayClientError::new(ReplayClientErrorKind::InvalidResponse)
                        })?
                        .into_bytes(),
                    *delivery.event().integrity_digest(),
                    delivery.event().sequence(),
                    replay_cursor_global_position(delivery.cursor())?,
                ));
            }
            if !has_more {
                return Ok(AppliedSuffix {
                    cursor: last,
                    last_event,
                });
            }
            let path = format!("/v1/replay/{}/read-page", wire::session_value(session_id));
            let page: ReadPageResponseWire = self
                .post_replay_json(
                    &path,
                    &ReadPageRequestWire {
                        limit: REPLAY_PAGE_LIMIT,
                    },
                )
                .await?;
            events = page.events;
            has_more = page.has_more;
        }
    }

    async fn post_resume_wire(
        &self,
        wire: &gocode_api::ReplayRetentionBaselineWireV2,
    ) -> Result<ResumeFromBaselineResponseWire, ReplayClientError> {
        let fields = wire.to_unauthenticated_fields();
        let body = json!({"baseline":{
            "schemaVersion":fields.schema_version,"authorityId":hex::encode(fields.authority_id),
            "principalId":fields.principal_id,"lineageId":hex::encode(fields.lineage_id),
            "runtimeSessionBindingDigest":hex::encode(fields.runtime_session_binding_digest),"replayScopeDigest":hex::encode(fields.replay_scope_digest),
            "aggregateKind":match fields.aggregate_kind { gocode_api::ApiReplayAggregateKind::Conversation=>"conversation",gocode_api::ApiReplayAggregateKind::TaskRun=>"taskRun" },"aggregateId":hex::encode(fields.aggregate_id),
            "sequence":fields.sequence,"version":fields.version,"baselineGlobalPosition":fields.baseline_global_position,
            "headEventId":hex::encode(fields.head_event_id),"headIntegrityDigest":hex::encode(fields.head_integrity_digest),"promotionCodec":fields.promotion_codec,
            "promotionProjectionBytes":URL_SAFE_NO_PAD.encode(fields.promotion_projection_bytes),"promotionProjectionDigest":hex::encode(fields.promotion_projection_digest),
            "retainedFloor":fields.retained_floor,"capturedHighWater":fields.captured_high_water,"retentionGeneration":fields.retention_generation,
            "retentionManifestDigest":hex::encode(fields.retention_manifest_digest),"issuedAtUnixMs":fields.issued_at_unix_ms,"expiresAtUnixMs":fields.expires_at_unix_ms,"witnessMac":hex::encode(fields.witness_mac)}});
        let encoded = serde_json::to_vec(&body)
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::InvalidRequest))?;
        if encoded.len() > 1024 * 1024 {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidRequest,
            ));
        }
        let response = self
            .authenticated_request(
                self.http_client()
                    .post(self.url("/v1/replay/resume-from-baseline")),
            )
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?
            .header(CONTENT_TYPE, "application/json")
            .body(encoded)
            .send()
            .await
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
        super::http::read_resume_json(response).await
    }
}

include!("resume_pending.rs");
include!("resume_validation.rs");
