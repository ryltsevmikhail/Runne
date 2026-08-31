impl SecureLocalHttpHost {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_project_workspace<T, C, P>(
        verified_tls: VerifiedLocalTls, health_state: HealthState, admission_state: AdmissionState,
        local_session_service: Arc<Mutex<runne_application::local_session::LocalSessionService>>,
        binding: runne_api::RuntimeSessionBinding, dynamic_session_binding: bool,
        clock: Arc<dyn Fn() -> Duration + Send + Sync>, runtime_profile_state: RuntimeProfileHttpState,
        task_run_state: TaskRunHttpState<T>, conversation_state: ConversationHttpState<C>,
        project_workspace_state: crate::project_workspace::ProjectWorkspaceHttpState<P>,
        replay_state: ReplayHttpState, operational_telemetry_state: OperationalTelemetryHttpState,
    ) -> Result<Self, SecureLocalHttpHostError>
    where
        T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
        C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
        P: runne_api::ProjectWorkspaceCommandHostPort + runne_api::ProjectWorkspaceQueryHostPort + 'static,
    {
        if runtime_profile_state.ordered_capability_digest() != *binding.stable().capability_digest() {
            return Err(SecureLocalHttpHostError::CapabilityDigestMismatch);
        }
        require_provider_credential_enrollment_admission(&runtime_profile_state)?;
        if !runtime_profile_state.advertises(OPERATIONAL_TELEMETRY_CAPABILITY_V1) {
            return Err(SecureLocalHttpHostError::OperationalTelemetryCapabilityMissing);
        }
        let session_auth = if dynamic_session_binding {
            SessionAuthLayer::new_dynamic(local_session_service.clone(), Arc::clone(&clock))
        } else {
            SessionAuthLayer::new(local_session_service.clone(), binding, Arc::clone(&clock))
        };
        let protected = Router::new()
            .merge(runtime_profile_session_router(runtime_profile_state))
            .merge(task_run_router(task_run_state))
            .merge(conversation_router(conversation_state))
            .merge(crate::project_workspace::project_workspace_router(project_workspace_state))
            .merge(replay_router(replay_state))
            .layer(axum_mw::from_fn_with_state(admission_state.clone(), admission_middleware))
            .layer(session_auth.clone()).layer(axum_mw::from_fn(request_id_middleware));
        let telemetry = operational_telemetry_router(operational_telemetry_state)
            .layer(axum_mw::from_fn_with_state(admission_state.clone(), admission_middleware))
            .layer(session_auth.clone()).layer(axum_mw::from_fn(no_store_response))
            .layer(axum_mw::from_fn(request_id_middleware));
        let protected = protected.merge(telemetry);
        let local_session_state = LocalSessionHttpState::new(local_session_service, clock, verified_tls);
        Ok(Self { router: Router::new().merge(health_router(health_state)).merge(create_local_session_bootstrap_router(local_session_state)).merge(protected) })
    }
}
