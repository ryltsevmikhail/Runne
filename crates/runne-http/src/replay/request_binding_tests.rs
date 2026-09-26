use runne_application::prohibited_content::ProhibitedContentPort;
use runne_store::schema::apply_migrations;
use std::sync::atomic::{AtomicI64, Ordering};

struct RotatingReplayAuthorization {
    epoch: Arc<AtomicI64>,
    runtime_authority: [u8; 16],
    generation: i64,
}

impl ReplayAuthorizationPort for RotatingReplayAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        if request.authority_id != self.runtime_authority
            || request.session_generation != self.generation
        {
            return Err(ReplayError::AuthorizationRevoked);
        }
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            self.epoch.load(Ordering::Acquire),
            Sensitivity::Sensitive,
        )
    }
}

struct AllowReplayDelivery;
impl ReplayDeliveryPrecommitGuard for AllowReplayDelivery {
    fn inspect(&self, _: &ReplaySession, _: &[ReplayEvent]) -> Result<(), ReplayError> {
        Ok(())
    }
}

struct AllowContent;
impl ProhibitedContentPort for AllowContent {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

fn authenticated_epoch(generation: u64, epoch: u64) -> AuthenticatedRuntimeSession {
    AuthenticatedRuntimeSession {
        binding: RuntimeSessionBinding::new(
            StableRuntimeBinding::new(
                uuid_v7(1),
                ApiPrincipalId::new("local-owner").unwrap(),
                EventLogLineageId::from_bytes(uuid_v7(2)),
                "gocode-ui-client/2",
                [3; 32],
                [4; 32],
            )
            .unwrap(),
            DaemonInstanceId::from_bytes(uuid_v7(5)),
            generation,
            uuid_v7(6),
            epoch,
            Sensitivity::Sensitive,
            [7; 32],
        )
        .unwrap(),
        expires_at_monotonic: Duration::from_secs(600),
    }
}

#[tokio::test]
async fn replay_http_uses_rotated_authenticated_epoch_and_fences_old_epoch() {
    const AUTHORITY: [u8; 16] = [0x44; 16];
    const GENERATION: i64 = 7;
    let connection =
        open_managed_connection(std::path::Path::new(":memory:"), ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let epoch = Arc::new(AtomicI64::new(1));
    let service = ReplayService::new(
        Arc::new(ReplayStore::new(connection)),
        [11; 32],
        EventLogLineageId::from_bytes(uuid_v7(2)),
        Arc::new(RotatingReplayAuthorization {
            epoch: Arc::clone(&epoch),
            runtime_authority: AUTHORITY,
            generation: GENERATION,
        }),
    );
    let state = ReplayHttpState::new(
        service,
        ReplayHttpBinding::new(AUTHORITY, GENERATION, 0).unwrap(),
        LimitsConfig::default(),
        Arc::new(AllowContent),
    );
    let old = authenticated_epoch(GENERATION as u64, 0);
    let current = authenticated_epoch(GENERATION as u64, 1);
    let scope_id = uuid_v7(9);
    let service = Arc::clone(&state.service);
    let open = move |binding: ReplayHttpBinding| {
        let service = Arc::clone(&service);
        async move {
            service
                .open_session(
                    "local-owner",
                    binding.session_generation,
                    &binding.authority_id,
                    binding.authorization_epoch,
                    1,
                    &scope_id,
                    None,
                    Arc::new(AllowReplayDelivery),
                )
                .await
        }
    };
    assert!(matches!(
        open(state.binding).await,
        Err(ReplayError::AuthorizationRevoked)
    ));
    let old_binding = state.binding_for_authenticated(&old).unwrap();
    assert!(matches!(
        open(old_binding).await,
        Err(ReplayError::AuthorizationRevoked)
    ));
    let current_binding = state.binding_for_authenticated(&current).unwrap();
    assert_eq!(current_binding.authority_id, AUTHORITY);
    let (session, _) = open(current_binding)
        .await
        .expect("rotated epoch opens replay");

    epoch.store(2, Ordering::Release);
    assert!(matches!(
        state
            .service
            .read_page(
                &session.session_id,
                "local-owner",
                GENERATION,
                &AUTHORITY,
                current_binding.authorization_epoch,
                10,
                Arc::new(AllowReplayDelivery),
            )
            .await,
        Err(ReplayError::AuthorizationRevoked)
    ));
    assert!(
        state
            .binding_for_authenticated(&authenticated_epoch(8, 1))
            .is_err()
    );

    let wrong_authority = ReplayHttpBinding::new([0x45; 16], GENERATION, 1).unwrap();
    assert!(matches!(
        open(wrong_authority).await,
        Err(ReplayError::AuthorizationRevoked)
    ));
}

#[tokio::test]
async fn duplicate_v2_resume_id_preserves_existing_lease_and_binding() {
    let authenticated = authenticated_epoch(7, 1);
    let connection =
        open_managed_connection(std::path::Path::new(":memory:"), ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let service = ReplayService::new(
        Arc::new(ReplayStore::new(connection)),
        [11; 32],
        *authenticated.binding.stable().lineage_id(),
        Arc::new(AvailableReplayAuthorization),
    );
    let state = ReplayHttpState::new(
        service,
        ReplayHttpBinding::new([0x44; 16], 7, 0).unwrap(),
        LimitsConfig::default(),
        Arc::new(AllowContent),
    );
    let session_id = [0x52; 16];
    let principal_id = "local-owner".to_owned();
    let first_binding = ReplayHttpBinding::new([0x44; 16], 7, 1).unwrap();
    let duplicate_binding = ReplayHttpBinding::new([0x44; 16], 7, 2).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

    state
        .retain_v2_session_permit(
            session_id,
            principal_id.clone(),
            state.quotas.reserve_session(&principal_id).unwrap(),
            deadline,
            first_binding,
        )
        .unwrap();
    assert!(matches!(
        state.claim_v2_resume_delivery(&session_id),
        V2ResumeDeliveryClaim::Delivered
    ));

    assert!(
        state
            .retain_v2_session_permit(
                session_id,
                principal_id,
                state.quotas.reserve_session("local-owner").unwrap(),
                deadline,
                duplicate_binding,
            )
            .is_err()
    );

    assert!(matches!(
        state
            .provisional_resume_sessions
            .lock()
            .unwrap()
            .get(&session_id),
        Some(V2ResumeLeaseState::Delivered)
    ));
    let retained_binding = state.provisional_resume_binding(&session_id).unwrap();
    assert_eq!(retained_binding.authority_id, first_binding.authority_id);
    assert_eq!(
        retained_binding.authorization_epoch,
        first_binding.authorization_epoch
    );
    assert!(
        state
            .session_permits
            .lock()
            .unwrap()
            .contains_key(&session_id)
    );
}
