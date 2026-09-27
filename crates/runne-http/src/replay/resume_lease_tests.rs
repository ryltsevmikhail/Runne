struct ReapingAuthorization {
    generation: std::sync::atomic::AtomicI64,
    epoch: std::sync::atomic::AtomicI64,
    transient_failures: std::sync::atomic::AtomicUsize,
    calls: std::sync::atomic::AtomicUsize,
    authority: [u8; 16],
}

impl ReplayAuthorizationPort for ReapingAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self
            .transient_failures
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            return Err(ReplayError::BackpressureExceeded);
        }
        if request.authority_id != self.authority
            || request.session_generation
                != self.generation.load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ReplayError::AuthorizationRevoked);
        }
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            self.epoch.load(std::sync::atomic::Ordering::SeqCst),
            Sensitivity::Sensitive,
        )
    }
}

async fn pending_resume_reaper(
    authorization: Arc<ReapingAuthorization>,
) -> (ReplayHttpState, [u8; 16], ReplayHttpBinding) {
    const AUTHORITY: [u8; 16] = [0x44; 16];
    let connection =
        open_managed_connection(std::path::Path::new(":memory:"), ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let service = ReplayService::new(
        Arc::new(ReplayStore::new(connection)),
        [11; 32],
        EventLogLineageId::from_bytes(uuid_v7(2)),
        authorization,
    );
    let state = ReplayHttpState::new(
        service,
        ReplayHttpBinding::new(AUTHORITY, 7, 0).unwrap(),
        LimitsConfig::default(),
        Arc::new(AllowContent),
    );
    let binding = ReplayHttpBinding::new(AUTHORITY, 7, 1).unwrap();
    let (session, _) = state
        .service
        .open_session(
            "local-owner",
            binding.session_generation,
            &binding.authority_id,
            binding.authorization_epoch,
            1,
            &uuid_v7(9),
            None,
            Arc::new(AllowReplayDelivery),
        )
        .await
        .unwrap();
    let session_id = session.session_id;
    state
        .retain_v2_session_permit(
            session_id,
            "local-owner".to_owned(),
            state.quotas.reserve_session("local-owner").unwrap(),
            tokio::time::Instant::now() + Duration::from_secs(30),
            binding,
        )
        .unwrap();
    assert!(matches!(
        state.claim_v2_resume_delivery(&session_id),
        V2ResumeDeliveryClaim::Delivered
    ));
    assert!(claim_v2_resume_reaping_state(
        &mut state.provisional_resume_sessions.lock().unwrap(),
        &session_id,
        V2ResumeLeaseState::Delivered,
    ));
    (state, session_id, binding)
}

fn assert_resume_permit_released(state: &ReplayHttpState, session_id: &[u8; 16]) {
    assert!(
        !state
            .session_permits
            .lock()
            .unwrap()
            .contains_key(session_id)
    );
    assert!(
        !state
            .provisional_resume_sessions
            .lock()
            .unwrap()
            .contains_key(session_id)
    );
    assert!(
        !state
            .provisional_resume_bindings
            .lock()
            .unwrap()
            .contains_key(session_id)
    );
}

#[tokio::test]
async fn rotated_authorization_stops_resume_reaping_and_releases_local_quota() {
    let authorization = Arc::new(ReapingAuthorization {
        generation: 7.into(),
        epoch: 1.into(),
        transient_failures: 0.into(),
        calls: 0.into(),
        authority: [0x44; 16],
    });
    let (state, session_id, binding) = pending_resume_reaper(Arc::clone(&authorization)).await;
    authorization
        .generation
        .store(8, std::sync::atomic::Ordering::SeqCst);
    authorization
        .epoch
        .store(2, std::sync::atomic::Ordering::SeqCst);

    tokio::time::timeout(
        Duration::from_millis(100),
        state.reap_v2_resume(session_id, "local-owner".to_owned(), true, binding),
    )
    .await
    .expect("revoked lease must terminate cleanup");

    assert_eq!(
        authorization
            .calls
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_resume_permit_released(&state, &session_id);
}

#[tokio::test]
async fn transient_resume_close_failure_retries_before_releasing_quota() {
    let authorization = Arc::new(ReapingAuthorization {
        generation: 7.into(),
        epoch: 1.into(),
        transient_failures: 0.into(),
        calls: 0.into(),
        authority: [0x44; 16],
    });
    let (state, session_id, binding) = pending_resume_reaper(Arc::clone(&authorization)).await;
    authorization
        .transient_failures
        .store(1, std::sync::atomic::Ordering::SeqCst);

    tokio::time::timeout(
        Duration::from_secs(3),
        state.reap_v2_resume(session_id, "local-owner".to_owned(), true, binding),
    )
    .await
    .expect("transient close error must retry");

    assert_eq!(
        authorization
            .calls
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_resume_permit_released(&state, &session_id);
}
