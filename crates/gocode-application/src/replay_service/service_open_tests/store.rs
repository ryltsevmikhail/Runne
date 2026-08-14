struct BlockingGapStore {
    started: Arc<Notify>,
    release: Arc<Notify>,
    baseline: ReplayRetentionBaselineCandidateV1,
}

struct AllowAuthorization;
struct AllowDelivery;
struct PublicAuthorization;

fn test_baseline_event(request: &ReplayBaselineResumeRequestV2) -> ReplayEvent {
    ReplayEvent {
        global_position: request.baseline_global_position(),
        event_id: [1; 16],
        aggregate_type: request.aggregate_type(),
        aggregate_id: *request.aggregate_id(),
        payload: vec![],
        timestamp: 1,
        event_type: "baseline".into(),
        sequence: i64::try_from(request.sequence()).unwrap(),
        sensitivity: 0,
        schema_version: 1,
        causation_id: None,
        command_id: [1; 16],
        idempotency_key: "baseline".into(),
        actor: "test".into(),
        integrity_digest: [1; 32],
        correlation_id: *request.aggregate_id(),
        correlation_type: request.aggregate_type(),
        integrity_profile: 1,
    }
}

fn accepted_promotion(request: &ReplayBaselineResumeRequestV2) -> ReplayAcceptedPromotionV2 {
    ReplayAcceptedPromotionV2::from_storage(ReplayAcceptedPromotionV2Parts {
        codec: 1,
        bytes: request.promotion_projection_bytes().to_vec(),
        digest: *request.promotion_projection_digest(),
        sequence: request.sequence(),
        version: request.version(),
        global_position: request.baseline_global_position(),
        head_event_id: *request.head_event_id(),
        head_integrity_digest: *request.head_integrity_digest(),
        captured_high_water: request.captured_high_water(),
    })
    .unwrap()
}

impl ReplayAuthorizationPort for AllowAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            request.expected_epoch,
            Sensitivity::Sensitive,
        )
    }
}

impl ReplayAuthorizationPort for PublicAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            request.expected_epoch,
            Sensitivity::Public,
        )
    }
}

impl ReplayDeliveryPrecommitGuard for AllowDelivery {
    fn inspect(&self, _: &ReplaySession, _: &[ReplayEvent]) -> Result<(), ReplayError> {
        Ok(())
    }
}

#[async_trait]
impl ReplayStorePort for BlockingGapStore {
    async fn resume_session_from_baseline_v2(
        &self,
        request: ReplayBaselineResumeRequestV2,
        _: &EventLogLineageId,
        _: &[u8; 32],
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>, ReplayEvent, ReplayAcceptedPromotionV2), ReplayError>
    {
        Ok((
            ReplaySession {
                session_id: [3; 16],
                principal_id: request.principal_id().to_owned(),
                session_generation: request.session_generation(),
                authority_id: *request.authority_id(),
                authorization_epoch: request.authorization_epoch(),
                aggregate_type: request.aggregate_type(),
                aggregate_id: *request.aggregate_id(),
                retained_floor: Some(request.retained_floor()),
                retention_generation: 0,
                high_water_position: request.captured_high_water(),
                next_page_position: None,
                last_delivered_position: None,
                last_acked_position: None,
                state: ReplayState::CatchingUp,
                high_water_ref: vec![],
                catch_up_completion: None,
                live_delivery_id: None,
                created_at: String::new(),
            },
            vec![],
            test_baseline_event(&request),
            accepted_promotion(&request),
        ))
    }

    async fn open_session(
        &self,
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: i32,
        _: &[u8; 16],
        _: Option<&ReplayCursor>,
        _: &EventLogLineageId,
        _: &[u8; 32],
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplayOpenResult, ReplayError> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(ReplayOpenResult::RetentionGap {
            baseline: self.baseline.clone(),
        })
    }

    async fn retention_manifest(
        &self,
        _: &EventLogLineageId,
        _: &[u8; 32],
    ) -> Result<RetentionManifest, ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }

    async fn read_page(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: usize,
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }

    async fn acknowledge(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: &ReplayCursor,
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(), ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }

    async fn complete_catch_up(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: &[u8; 32],
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Option<ReplayEvent>), ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }

    async fn continue_live(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplaySession, ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }

    async fn poll_live(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }

    async fn close_session(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
    ) -> Result<(), ReplayError> {
        Err(ReplayError::Storage("unused".into()))
    }
}
