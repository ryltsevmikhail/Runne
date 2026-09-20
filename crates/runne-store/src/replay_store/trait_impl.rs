#[async_trait]
#[allow(clippy::too_many_arguments)]
impl ReplayStorePort for ReplayStore {
    async fn resume_session_from_baseline_v2(
        &self,
        request: runne_application::ports::ReplayBaselineResumeRequestV2,
        lineage_id: &EventLogLineageId,
        server_secret: &[u8; 32],
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>, ReplayEvent, runne_application::ports::ReplayAcceptedPromotionV2), ReplayError> {
        self.resume_session_from_baseline_v2_impl(
            request,
            lineage_id,
            server_secret,
            delivery_guard,
        )
        .await
    }

    fn session_delivery_scope(&self, session_id: &[u8; 16]) -> Option<(i32, [u8; 16])> {
        self.session_delivery_scope_impl(session_id)
    }

    async fn open_session(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
        from_cursor: Option<&ReplayCursor>,
        lineage_id: &EventLogLineageId,
        server_secret: &[u8; 32],
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplayOpenResult, ReplayError> {
        self.open_session_impl(
            principal_id,
            session_generation,
            authority_id,
            authorization_epoch,
            aggregate_type,
            aggregate_id,
            from_cursor,
            lineage_id,
            server_secret,
            delivery_guard,
        )
        .await
    }

    async fn retention_manifest(
        &self,
        lineage_id: &EventLogLineageId,
        server_secret: &[u8; 32],
    ) -> Result<RetentionManifest, ReplayError> {
        self.retention_manifest_impl(lineage_id, server_secret)
            .await
    }

    async fn read_page(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        limit: usize,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        self.read_page_impl(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
            limit,
            delivery_guard,
        )
        .await
    }

    async fn acknowledge(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        cursor: &ReplayCursor,
        authorization_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(), ReplayError> {
        self.acknowledge_impl(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
            cursor,
            authorization_guard,
        )
        .await
    }

    async fn complete_catch_up(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        server_secret: &[u8; 32],
        authorization_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Option<ReplayEvent>), ReplayError> {
        self.complete_catch_up_impl(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
            server_secret,
            authorization_guard,
        )
        .await
    }

    async fn continue_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        authorization_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplaySession, ReplayError> {
        self.continue_live_impl(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
            authorization_guard,
        )
        .await
    }

    async fn poll_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        self.poll_live_impl(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
            delivery_guard,
        )
        .await
    }

    async fn close_session(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<(), ReplayError> {
        self.close_session_impl(session_id, principal_id, generation, authority_id, epoch)
            .await
    }
}
