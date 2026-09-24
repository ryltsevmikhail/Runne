/// Builds the TLS-gated local-session bootstrap surface without changing the
/// legacy bearer-protected production router before the Task 4 cutover.
#[allow(dead_code)] // Used by SecureLocalHttpHost when Task 4B adds TLS serving.
pub(crate) fn create_local_session_bootstrap_router(state: LocalSessionHttpState) -> Router {
    local_session_router(state)
}

/// Crate-private local runtime HTTP composition following TLS verification.
///
/// The host is built only after the crate-owned TLS serving boundary supplies
/// its verified capability. It never returns an Axum `Router`.
pub(crate) struct SecureLocalHttpHost {
    router: Router,
}

/// Rejected inconsistent local runtime profile configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SecureLocalHttpHostError {
    /// The advertised ordered capabilities do not match the authenticated binding.
    #[error("runtime profile capability digest does not match session binding")]
    CapabilityDigestMismatch,
    /// Telemetry state was supplied without its advertised capability.
    #[error("operational telemetry capability is not advertised")]
    OperationalTelemetryCapabilityMissing,
    /// V2 credential enrollment needs a transport-owned authenticated admission.
    #[error("provider credential enrollment V2 admission is unavailable")]
    ProviderCredentialEnrollmentAdmissionMissing,
}

impl SecureLocalHttpHost {
    /// Composes bootstrap, health, and every canonical protected route over one
    /// shared local-session service after verified TLS listener setup.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)] // Called by the crate-owned TLS serving boundary in Task 4B.
    pub(crate) fn new<T, C>(
        verified_tls: VerifiedLocalTls,
        health_state: HealthState,
        admission_state: AdmissionState,
        local_session_service: Arc<Mutex<runne_application::local_session::LocalSessionService>>,
        binding: runne_api::RuntimeSessionBinding,
        dynamic_session_binding: bool,
        clock: Arc<dyn Fn() -> Duration + Send + Sync>,
        runtime_profile_state: RuntimeProfileHttpState,
        task_run_state: TaskRunHttpState<T>,
        conversation_state: ConversationHttpState<C>,
        replay_state: ReplayHttpState,
    ) -> Result<Self, SecureLocalHttpHostError>
    where
        T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
        C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
    {
        Self::new_with_operational_telemetry(
            verified_tls,
            health_state,
            admission_state,
            local_session_service,
            binding,
            dynamic_session_binding,
            clock,
            runtime_profile_state,
            task_run_state,
            conversation_state,
            replay_state,
            None,
        )
    }

    /// Composes the local host with optional capability-gated telemetry state.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_operational_telemetry<T, C>(
        verified_tls: VerifiedLocalTls,
        health_state: HealthState,
        admission_state: AdmissionState,
        local_session_service: Arc<Mutex<runne_application::local_session::LocalSessionService>>,
        binding: runne_api::RuntimeSessionBinding,
        dynamic_session_binding: bool,
        clock: Arc<dyn Fn() -> Duration + Send + Sync>,
        runtime_profile_state: RuntimeProfileHttpState,
        task_run_state: TaskRunHttpState<T>,
        conversation_state: ConversationHttpState<C>,
        replay_state: ReplayHttpState,
        operational_telemetry_state: Option<OperationalTelemetryHttpState>,
    ) -> Result<Self, SecureLocalHttpHostError>
    where
        T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
        C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
    {
        if runtime_profile_state.ordered_capability_digest()
            != *binding.stable().capability_digest()
        {
            return Err(SecureLocalHttpHostError::CapabilityDigestMismatch);
        }
        require_provider_credential_enrollment_admission(&runtime_profile_state, false)?;
        let advertises_telemetry = runtime_profile_state.advertises(OPERATIONAL_TELEMETRY_CAPABILITY_V1);
        if operational_telemetry_state.is_some() && !advertises_telemetry {
            return Err(SecureLocalHttpHostError::OperationalTelemetryCapabilityMissing);
        }
        let session_auth = if dynamic_session_binding {
            SessionAuthLayer::new_dynamic(local_session_service.clone(), Arc::clone(&clock))
        } else {
            SessionAuthLayer::new(local_session_service.clone(), binding, Arc::clone(&clock))
        };
        let task_run_routes = crate::task_runs::mount_prompted_submit_for_profile(
            canonical_task_run_router(task_run_state.clone()),
            task_run_state,
            &runtime_profile_state,
        );
        let protected = Router::new()
            .merge(runtime_profile_session_router(
                runtime_profile_state.clone(),
            ))
            .merge(task_run_routes)
            .merge(conversation_router(conversation_state))
            .merge(replay_router(replay_state))
            .layer(axum_mw::from_fn_with_state(
                admission_state.clone(),
                admission_middleware,
            ))
            .layer(session_auth.clone())
            .layer(axum_mw::from_fn(request_id_middleware));
        let local_session_state =
            LocalSessionHttpState::new(local_session_service, Arc::clone(&clock), verified_tls);
        let protected = match operational_telemetry_state {
            Some(state) if advertises_telemetry => protected.merge(
                operational_telemetry_router(state)
                    .layer(axum_mw::from_fn_with_state(
                        admission_state,
                        admission_middleware,
                    ))
                    .layer(session_auth)
                    .layer(axum_mw::from_fn(no_store_response))
                    .layer(axum_mw::from_fn(request_id_middleware)),
            ),
            Some(_) | None => protected,
        };
        Ok(Self {
            router: Router::new()
                .merge(health_router(health_state))
                .merge(create_local_session_bootstrap_router(local_session_state))
                .merge(protected),
        })
    }

    /// Consumes the host inside the crate-owned TLS accept loop.
    pub(crate) fn into_router(self) -> Router {
        self.router
    }

    #[cfg(test)]
    fn router_for_test(&self) -> Router {
        self.router.clone()
    }
}

/// Builds the production canonical HTTP surface.
///
/// `/health` remains unauthenticated. Every `/v1/task-runs/*` route is wrapped
/// by one request identity, bearer authentication, and admission gating.
pub fn create_router<H>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<H>,
) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    let protected = protected_task_run_router(token, admission_state, task_run_state);
    Router::new()
        .merge(health_router(health_state))
        .merge(protected)
}

/// Builds a TaskRun router whose prompted v2 submit route follows the supplied
/// runtime profile capability set.
pub fn create_router_with_task_run_profile<H>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<H>,
    runtime_profile_state: RuntimeProfileHttpState,
) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    let task_run_routes = crate::task_runs::mount_prompted_submit_for_profile(
        task_run_router(task_run_state.clone()),
        task_run_state,
        &runtime_profile_state,
    );
    let protected = Router::new()
        .merge(task_run_routes)
        .layer(axum_mw::from_fn_with_state(admission_state, admission_middleware))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new().merge(health_router(health_state)).merge(protected)
}

/// Builds the production canonical Project and Workspace surface.
pub fn create_router_with_project_workspace<H>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    project_workspace_state: ProjectWorkspaceHttpState<H>,
) -> Router
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort + 'static,
{
    let protected = project_workspace_router(project_workspace_state)
        .layer(axum_mw::from_fn_with_state(
            admission_state,
            admission_middleware,
        ))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new()
        .merge(health_router(health_state))
        .merge(protected)
}

/// Builds the authenticated Workspace file projection surface.
pub fn create_router_with_workspace_files<H>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    workspace_file_state: WorkspaceFileHttpState<H>,
) -> Router
where
    H: WorkspaceFileHostPort + 'static,
{
    let protected = workspace_file_router(workspace_file_state)
        .layer(axum_mw::from_fn_with_state(admission_state, admission_middleware))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new().merge(health_router(health_state)).merge(protected)
}

/// Builds the authenticated Workspace change and diff projection surface.
pub fn create_router_with_workspace_diffs<H>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    workspace_diff_state: WorkspaceDiffHttpState<H>,
) -> Router
where
    H: WorkspaceDiffHostPort + 'static,
{
    let protected = workspace_diff_router(workspace_diff_state)
        .layer(axum_mw::from_fn_with_state(admission_state, admission_middleware))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new().merge(health_router(health_state)).merge(protected)
}

/// Builds the production canonical TaskRun and Conversation message surface.
pub fn create_router_with_conversations<T, C>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<T>,
    conversation_state: ConversationHttpState<C>,
    runtime_profile_state: RuntimeProfileHttpState,
    _replay_state: ReplayHttpState,
) -> Router
where
    T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
    C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
{
    let task_run_routes = crate::task_runs::mount_prompted_submit_for_profile(
        task_run_router(task_run_state.clone()),
        task_run_state,
        &runtime_profile_state,
    );
    let protected = Router::new()
        .merge(runtime_profile_router(runtime_profile_state))
        .merge(task_run_routes)
        .merge(conversation_router(conversation_state))
        .layer(axum_mw::from_fn_with_state(
            admission_state,
            admission_middleware,
        ))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new()
        .merge(health_router(health_state))
        .merge(protected)
}
