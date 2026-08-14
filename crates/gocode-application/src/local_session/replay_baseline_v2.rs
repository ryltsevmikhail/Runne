/// Closed, authenticated facts that may start a V2 baseline-resume replay.
pub(crate) struct AuthenticatedReplayBaselineResumeV2 {
    aggregate_kind: gocode_api::ApiReplayAggregateKind,
    aggregate_id: [u8; 16],
    promotion_projection_bytes: Vec<u8>,
    promotion_projection_digest: [u8; 32],
    sequence: u64,
    version: u64,
    baseline_global_position: i64,
    head_event_id: [u8; 16],
    head_integrity_digest: [u8; 32],
    retained_floor: i64,
    captured_high_water: i64,
    retention_generation: u64,
    retention_manifest_digest: [u8; 32],
}

impl AuthenticatedReplayBaselineResumeV2 {
    pub(crate) const fn aggregate_kind(&self) -> gocode_api::ApiReplayAggregateKind {
        self.aggregate_kind
    }
    pub(crate) const fn aggregate_id(&self) -> [u8; 16] {
        self.aggregate_id
    }
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) const fn version(&self) -> u64 {
        self.version
    }
    pub(crate) const fn baseline_global_position(&self) -> i64 {
        self.baseline_global_position
    }
    pub(crate) const fn head_event_id(&self) -> [u8; 16] {
        self.head_event_id
    }
    pub(crate) const fn head_integrity_digest(&self) -> [u8; 32] {
        self.head_integrity_digest
    }
    pub(crate) const fn retained_floor(&self) -> i64 {
        self.retained_floor
    }
    pub(crate) const fn captured_high_water(&self) -> i64 {
        self.captured_high_water
    }
    pub(crate) const fn retention_generation(&self) -> u64 {
        self.retention_generation
    }
    pub(crate) const fn retention_manifest_digest(&self) -> [u8; 32] {
        self.retention_manifest_digest
    }
    pub(crate) fn promotion_projection_bytes(&self) -> &[u8] {
        &self.promotion_projection_bytes
    }
    pub(crate) const fn promotion_projection_digest(&self) -> [u8; 32] {
        self.promotion_projection_digest
    }
}

impl AuthenticatedReplayBaselineIssuer {
    /// Signs one semantic V2 baseline while this exact authenticated session remains live.
    pub(crate) fn issue_v2(
        &self,
        scope: gocode_domain::replay::ReplayScope,
        candidate: crate::replay_service::ReplayRetentionBaselineCandidateV2,
        now_monotonic: std::time::Duration,
        issued_at_unix_ms: u64,
        requested_expires_at_unix_ms: u64,
    ) -> Result<gocode_api::ReplayRetentionBaselineWireV2, LocalSessionError> {
        if self.state.revoked.load(Ordering::Acquire) || now_monotonic >= self.expires_at_monotonic
        {
            return Err(LocalSessionError::Unauthorized);
        }
        let expires = replay_baseline_v2_expiry(
            self.expires_at_monotonic,
            now_monotonic,
            issued_at_unix_ms,
            requested_expires_at_unix_ms,
        )?;
        let (aggregate_kind, aggregate_id) = replay_baseline_scope(&scope)?;
        let (candidate_kind, candidate_id, promotion_digest) =
            promotion_identity(candidate.promotion_projection());
        if candidate_kind != aggregate_kind || candidate_id != aggregate_id {
            return Err(LocalSessionError::Unauthorized);
        }
        let stable = self.binding.stable();
        let unsigned = gocode_api::ReplayRetentionBaselineWireV2::from_unauthenticated_fields(
            gocode_api::UnauthenticatedReplayRetentionBaselineFieldsV2 {
                schema_version: 2,
                authority_id: *stable.authority_id(),
                principal_id: stable.principal_id().as_str().to_owned(),
                lineage_id: *stable.lineage_id().as_bytes(),
                runtime_session_binding_digest: self.binding.canonical_digest(),
                replay_scope_digest: scope.canonical_digest(),
                aggregate_kind,
                aggregate_id,
                sequence: candidate.sequence(),
                version: candidate.version(),
                baseline_global_position: candidate.baseline_global_position(),
                head_event_id: candidate.head_event_id(),
                head_integrity_digest: candidate.head_integrity_digest(),
                promotion_codec: 1,
                promotion_projection_bytes: candidate.promotion_projection_bytes().to_vec(),
                promotion_projection_digest: promotion_digest,
                retained_floor: candidate.retained_floor(),
                captured_high_water: candidate.captured_high_water(),
                retention_generation: candidate.retention_generation(),
                retention_manifest_digest: candidate.retention_manifest_digest(),
                issued_at_unix_ms,
                expires_at_unix_ms: expires,
                witness_mac: [0; 32],
            },
        );
        gocode_api::validate_unauthenticated_replay_retention_baseline_v2(
            &unsigned,
            aggregate_kind,
            &aggregate_id,
        )
        .map_err(|_| LocalSessionError::Unauthorized)?;
        let mut fields = unsigned.to_unauthenticated_fields();
        fields.witness_mac = self
            .authority
            .replay_baseline_v2_mac(fields.runtime_session_binding_digest, &unsigned)?;
        Ok(gocode_api::ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields))
    }

    /// Re-authenticates one exact V2 baseline before beginning a resume.
    pub(crate) fn verify_v2_for_resume(
        &self,
        scope: &gocode_domain::replay::ReplayScope,
        wire: &gocode_api::ReplayRetentionBaselineWireV2,
        now_monotonic: std::time::Duration,
        now_unix_ms: u64,
    ) -> Result<AuthenticatedReplayBaselineResumeV2, LocalSessionError> {
        if self.state.revoked.load(Ordering::Acquire) || now_monotonic >= self.expires_at_monotonic
        {
            return Err(LocalSessionError::Unauthorized);
        }
        let (aggregate_kind, aggregate_id) = replay_baseline_scope(scope)?;
        gocode_api::validate_unauthenticated_replay_retention_baseline_v2(
            wire,
            aggregate_kind,
            &aggregate_id,
        )
        .map_err(|_| LocalSessionError::Unauthorized)?;
        let fields = wire.to_unauthenticated_fields();
        let stable = self.binding.stable();
        if fields.authority_id != *stable.authority_id()
            || fields.principal_id != stable.principal_id().as_str()
            || fields.lineage_id != *stable.lineage_id().as_bytes()
            || fields.replay_scope_digest != scope.canonical_digest()
            || now_unix_ms < fields.issued_at_unix_ms
            || now_unix_ms >= fields.expires_at_unix_ms
        {
            return Err(LocalSessionError::Unauthorized);
        }
        let binding_digest = self.binding.canonical_digest();
        let expected_mac = self
            .authority
            .replay_baseline_v2_mac(binding_digest, wire)?;
        if !bool::from(binding_digest.ct_eq(&fields.runtime_session_binding_digest))
            || !bool::from(expected_mac.ct_eq(&fields.witness_mac))
        {
            return Err(LocalSessionError::Unauthorized);
        }
        Ok(AuthenticatedReplayBaselineResumeV2 {
            aggregate_kind,
            aggregate_id,
            promotion_projection_bytes: fields.promotion_projection_bytes,
            promotion_projection_digest: fields.promotion_projection_digest,
            sequence: fields.sequence,
            version: fields.version,
            baseline_global_position: fields.baseline_global_position,
            head_event_id: fields.head_event_id,
            head_integrity_digest: fields.head_integrity_digest,
            retained_floor: fields.retained_floor,
            captured_high_water: fields.captured_high_water,
            retention_generation: fields.retention_generation,
            retention_manifest_digest: fields.retention_manifest_digest,
        })
    }
}

impl LocalSessionService {
    /// Mints an opaque V2 resume context from this service's process-local clock.
    pub fn replay_resume_context_v2(
        &self,
        issuer: &AuthenticatedReplayBaselineIssuer,
    ) -> Result<AuthenticatedReplayResumeContextV2, LocalSessionError> {
        if !self
            .sessions
            .values()
            .any(|session| Arc::ptr_eq(&session.issuer_state, &issuer.state))
        {
            return Err(LocalSessionError::Unauthorized);
        }
        let origin = self.trusted_clock_origin;
        Ok(AuthenticatedReplayResumeContextV2 {
            issuer: issuer.clone(),
            monotonic_clock: Arc::new(move || origin.elapsed()),
            wall_clock: Arc::new(system_time_unix_ms),
        })
    }

    #[cfg(test)]
    pub(crate) fn replay_resume_context_v2_for_test(
        &self,
        issuer: &AuthenticatedReplayBaselineIssuer,
        monotonic_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
        wall_clock: Arc<dyn Fn() -> Result<u64, LocalSessionError> + Send + Sync>,
    ) -> Result<AuthenticatedReplayResumeContextV2, LocalSessionError> {
        let mut context = self.replay_resume_context_v2(issuer)?;
        context.monotonic_clock = monotonic_clock;
        context.wall_clock = wall_clock;
        Ok(context)
    }
}

impl AuthenticatedReplayResumeContextV2 {
    pub(crate) fn issuer(&self) -> &AuthenticatedReplayBaselineIssuer {
        &self.issuer
    }

    pub(crate) fn now_monotonic(&self) -> std::time::Duration {
        (self.monotonic_clock)()
    }

    pub(crate) fn now_unix_ms(&self) -> Result<u64, LocalSessionError> {
        (self.wall_clock)()
    }
}

fn system_time_unix_ms() -> Result<u64, LocalSessionError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .map_err(|_| LocalSessionError::Unauthorized)
}

fn replay_baseline_v2_expiry(
    session_expires_at: std::time::Duration,
    now_monotonic: std::time::Duration,
    issued_at_unix_ms: u64,
    requested_expires_at_unix_ms: u64,
) -> Result<u64, LocalSessionError> {
    let max_ttl = session_expires_at
        .saturating_sub(now_monotonic)
        .as_millis()
        .min(30_000);
    let expires = requested_expires_at_unix_ms
        .min(issued_at_unix_ms.saturating_add(u64::try_from(max_ttl).unwrap_or(0)));
    (expires > issued_at_unix_ms)
        .then_some(expires)
        .ok_or(LocalSessionError::Unauthorized)
}

fn promotion_identity(
    projection: &gocode_api::UnauthenticatedReplayPromotionProjectionV1,
) -> (gocode_api::ApiReplayAggregateKind, [u8; 16], [u8; 32]) {
    match projection.view() {
        gocode_api::ReplayPromotionProjectionViewV1::Conversation(value) => (
            gocode_api::ApiReplayAggregateKind::Conversation,
            value.aggregate_id(),
            *value.projection_digest(),
        ),
        gocode_api::ReplayPromotionProjectionViewV1::TaskRun(value) => (
            gocode_api::ApiReplayAggregateKind::TaskRun,
            value.aggregate_id(),
            *value.promotion_digest(),
        ),
    }
}

impl RuntimeSessionAuthority {
    fn replay_baseline_v2_mac(
        &self,
        binding_digest: [u8; 32],
        wire: &gocode_api::ReplayRetentionBaselineWireV2,
    ) -> Result<[u8; 32], LocalSessionError> {
        let mut derive = HmacSha256::new_from_slice(self.0.as_ref()).expect("fixed HMAC key");
        derive.update(gocode_api::REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V2);
        derive.update(&binding_digest);
        let key: [u8; 32] = derive.finalize().into_bytes().into();
        let mut mac = HmacSha256::new_from_slice(&key).expect("fixed HMAC key");
        mac.update(
            &gocode_api::replay_retention_baseline_v2_transcript(wire)
                .map_err(|_| LocalSessionError::Unauthorized)?,
        );
        Ok(mac.finalize().into_bytes().into())
    }
}
