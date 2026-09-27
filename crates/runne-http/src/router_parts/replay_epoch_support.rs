struct CurrentSessionReplayAuthorization {
    local_session: Arc<Mutex<LocalSessionService>>,
    runtime_authority: [u8; 16],
}

impl ReplayAuthorizationPort for CurrentSessionReplayAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        if request.authority_id != self.runtime_authority {
            return Err(ReplayError::AuthorizationRevoked);
        }
        let generation = u64::try_from(request.session_generation)
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let current = self
            .local_session
            .lock()
            .map_err(|_| ReplayError::AuthorizationRevoked)?
            .current_replay_authorization(&request.principal_id, generation)
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            i64::try_from(current.authorization_epoch())
                .map_err(|_| ReplayError::AuthorizationRevoked)?,
            current.sensitivity_ceiling(),
        )
    }
}

fn replay_state_for_session(
    binding: &runne_api::RuntimeSessionBinding,
    local_session: Arc<Mutex<LocalSessionService>>,
    configured_replay_authority: [u8; 16],
    authorized_replay_authority: [u8; 16],
) -> ReplayHttpState {
    let connection =
        open_managed_connection(std::path::Path::new(":memory:"), ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let service = ReplayService::new(
        Arc::new(ReplayStore::new(connection)),
        [11; 32],
        *binding.stable().lineage_id(),
        Arc::new(CurrentSessionReplayAuthorization {
            local_session,
            runtime_authority: authorized_replay_authority,
        }),
    );
    ReplayHttpState::new(
        service,
        crate::replay::ReplayHttpBinding::new(
            configured_replay_authority,
            i64::try_from(binding.ephemeral().launch_generation()).unwrap(),
            0,
        )
        .unwrap(),
        crate::limits::LimitsConfig::default(),
        Arc::new(AvailableGuard),
    )
}

fn binding_after_enrollment_rotation(
    current: &runne_api::RuntimeSessionBinding,
    launch_generation: u64,
    authorization_epoch: u64,
) -> runne_api::RuntimeSessionBinding {
    let mut session_id = *current.ephemeral().session_id();
    session_id[15] = session_id[15].wrapping_add(1);
    runne_api::RuntimeSessionBinding::new(
        current.stable().clone(),
        current.ephemeral().daemon_instance_id(),
        launch_generation,
        session_id,
        authorization_epoch,
        current.ephemeral().sensitivity_ceiling(),
        *current.certificate_sha256(),
    )
    .unwrap()
}

fn host_with_protected_replay_session(
    configured_replay_authority: [u8; 16],
    authorized_replay_authority: [u8; 16],
) -> (
    SecureLocalHttpHost,
    runne_api::RuntimeSessionBinding,
    Arc<Mutex<LocalSessionService>>,
) {
    let binding = binding();
    let generation_store =
        TestEnrollmentGenerationStore::at_generation(binding.ephemeral().launch_generation());
    let local_session = protected_session_service(binding.clone(), Arc::clone(&generation_store));
    let replay_state = replay_state_for_session(
        &binding,
        Arc::clone(&local_session),
        configured_replay_authority,
        authorized_replay_authority,
    );
    let host = SecureLocalHttpHost::new(
        VerifiedLocalTls::from_verified_listener(),
        HealthState {
            recovery_state: crate::health::RecoveryState::Ready,
        },
        AdmissionState::new(crate::health::RecoveryState::Ready),
        Arc::clone(&local_session),
        binding.clone(),
        true,
        clock(),
        profile_state_with_capabilities(CAPABILITIES),
        TaskRunHttpState::new(
            UnavailableTaskRunHost,
            ApiActor::new("runne-http-test").unwrap(),
        ),
        ConversationHttpState::new(
            UnavailableConversationHost,
            ApiActor::new("runne-http-test").unwrap(),
        ),
        replay_state,
    )
    .unwrap();
    (host, binding, local_session)
}

fn runtime_authority_for_replay_tests() -> [u8; 16] {
    [0x44; 16]
}

fn replay_test_authority_mismatch() -> [u8; 16] {
    [0x45; 16]
}

fn rotated_binding_for_test(
    current: &runne_api::RuntimeSessionBinding,
) -> runne_api::RuntimeSessionBinding {
    binding_after_enrollment_rotation(
        current,
        current.ephemeral().launch_generation() + 1,
        current.ephemeral().authorization_epoch() + 1,
    )
}

fn authorize_request(request: Request<Body>, authority: [u8; 32]) -> Request<Body> {
    let mut request = request;
    request.headers_mut().insert(
        "authorization",
        format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority))
            .parse()
            .unwrap(),
    );
    request
}

fn open_conversation_request() -> Request<Body> {
    json_request(
        "/v1/replay/open-session",
        serde_json::json!({
            "aggregateType": "conversation",
            "aggregateId": "018f2e3a-7000-7000-8000-000000000001"
        }),
    )
}

fn rotate_protected_session(
    sessions: &Arc<Mutex<LocalSessionService>>,
    current: &runne_api::RuntimeSessionBinding,
    bootstrap_secret: [u8; 32],
) -> runne_api::RuntimeSessionBinding {
    let mut sessions = sessions.lock().unwrap();
    let reserved = sessions.reserve_protected_enrollment_generation().unwrap();
    let next = rotated_binding_for_test(current);
    assert_eq!(reserved, next.ephemeral().launch_generation());
    sessions
        .rotate_protected_enrollment_epoch(
            current,
            next.clone(),
            bootstrap_secret,
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap();
    next
}

#[tokio::test]
async fn dynamic_replay_auth_accepts_protected_generation_rotation_and_fences_old_sessions() {
    let runtime_authority = runtime_authority_for_replay_tests();
    let (host, initial, local_session) =
        host_with_protected_replay_session(runtime_authority, runtime_authority);
    let app = host.router_for_test();
    let old_authority = bootstrap_authority(&app, &initial).await;
    let generation_eight = rotate_protected_session(&local_session, &initial, [0x33; 32]);

    let old_auth = app
        .clone()
        .oneshot(authorize_request(
            open_conversation_request(),
            old_authority,
        ))
        .await
        .unwrap();
    assert_eq!(old_auth.status(), StatusCode::UNAUTHORIZED);

    let authority_eight =
        bootstrap_authority_with(&app, &generation_eight, [0x33; 32], [11; 32]).await;
    let opened = app
        .clone()
        .oneshot(authorize_request(
            open_conversation_request(),
            authority_eight,
        ))
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::OK);
    let opened: serde_json::Value =
        serde_json::from_slice(&to_bytes(opened.into_body(), 8192).await.unwrap()).unwrap();
    let retained_session = opened["sessionId"].as_str().unwrap().to_owned();

    let generation_nine = rotate_protected_session(&local_session, &generation_eight, [0x55; 32]);
    let authority_nine =
        bootstrap_authority_with(&app, &generation_nine, [0x55; 32], [12; 32]).await;
    let current_open = app
        .clone()
        .oneshot(authorize_request(
            open_conversation_request(),
            authority_nine,
        ))
        .await
        .unwrap();
    assert_eq!(current_open.status(), StatusCode::OK);

    let retained_read = app
        .oneshot(authorize_request(
            json_request(
                &format!("/v1/replay/{retained_session}/read-page"),
                serde_json::json!({ "limit": 10 }),
            ),
            authority_eight,
        ))
        .await
        .unwrap();
    assert_eq!(retained_read.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replay_rejects_a_fixed_runtime_authority_mismatch() {
    let (host, binding, _) = host_with_protected_replay_session(
        replay_test_authority_mismatch(),
        runtime_authority_for_replay_tests(),
    );
    let app = host.router_for_test();
    let authority = bootstrap_authority(&app, &binding).await;
    let response = app
        .oneshot(authorize_request(open_conversation_request(), authority))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
