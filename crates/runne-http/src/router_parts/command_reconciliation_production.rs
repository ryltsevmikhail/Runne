impl SecureLocalHttpHost {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_project_workspace_and_command_reconciliation<T, C, P, R, F, D, Q, E, A>(
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
        project_workspace_state: crate::project_workspace::ProjectWorkspaceHttpState<P>,
        workspace_file_state: crate::workspace_files::WorkspaceFileHttpState<F>,
        workspace_diff_state: crate::workspace_diffs::WorkspaceDiffHttpState<D>,
        process_state: ProcessHttpState<Q>,
        editor_state: crate::editors::WorkspaceEditorHttpState<E>,
        reconciliation_state: CommandReconciliationHttpState<R>,
        approval_state: ApprovalHttpState<A>,
        replay_state: ReplayHttpState,
        operational_telemetry_state: OperationalTelemetryHttpState,
        enrollment_routes: Option<Router>,
    ) -> Result<Self, SecureLocalHttpHostError>
    where
        T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
        C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
        P: runne_api::ProjectWorkspaceCommandHostPort
            + runne_api::ProjectWorkspaceQueryHostPort
            + 'static,
        R: runne_api::CommandReconciliationHostPort + 'static,
        F: runne_api::WorkspaceFileHostPort + 'static,
        D: runne_api::WorkspaceDiffHostPort + 'static,
        Q: runne_api::ProcessHostPort + 'static,
        E: runne_api::WorkspaceEditorHostPort + 'static,
        A: ApprovalQueryHostPort + ApprovalCommandHostPort + 'static,
    {
        if runtime_profile_state.ordered_capability_digest()
            != *binding.stable().capability_digest()
        {
            return Err(SecureLocalHttpHostError::CapabilityDigestMismatch);
        }
        require_provider_credential_enrollment_admission(
            &runtime_profile_state,
            enrollment_routes.is_some(),
        )?;
        if !runtime_profile_state.advertises(OPERATIONAL_TELEMETRY_CAPABILITY_V1) {
            return Err(SecureLocalHttpHostError::OperationalTelemetryCapabilityMissing);
        }
        let process_capability_advertised =
            runtime_profile_state.advertises(runne_api::PROCESS_CONTROL_CAPABILITY_V1);
        let editor_capability_advertised = runtime_profile_state
            .advertises(runne_api::WORKSPACE_EDITOR_CAPABILITY_V1);
        let task_run_routes = crate::task_runs::mount_prompted_submit_for_profile(
            task_run_router(task_run_state.clone()),
            task_run_state,
            &runtime_profile_state,
        );
        let session_auth = if dynamic_session_binding {
            SessionAuthLayer::new_dynamic(local_session_service.clone(), Arc::clone(&clock))
        } else {
            SessionAuthLayer::new(local_session_service.clone(), binding, Arc::clone(&clock))
        };
        let protected = Router::new()
            .merge(runtime_profile_session_router(runtime_profile_state))
            .merge(task_run_routes)
            .merge(conversation_router(conversation_state))
            .merge(crate::project_workspace::project_workspace_router(
                project_workspace_state,
            ))
            .merge(approval_router(approval_state))
            .merge(crate::workspace_files::workspace_file_router(
                workspace_file_state,
            ))
            .merge(crate::workspace_diffs::workspace_diff_router(
                workspace_diff_state,
            ))
            .merge(replay_router(replay_state));
        let protected = mount_process_routes(protected, process_state, process_capability_advertised);
        let protected = mount_editor_routes(protected, editor_state, editor_capability_advertised);
        let protected = mount_provider_credential_enrollment_routes(protected, enrollment_routes)
        .layer(axum_mw::from_fn_with_state(
            admission_state.clone(),
            admission_middleware,
        ))
        .layer(session_auth.clone())
        .layer(axum_mw::from_fn(request_id_middleware));
        let reconciliation = command_reconciliation_router(reconciliation_state)
            .layer(axum_mw::from_fn_with_state(
                admission_state.clone(),
                admission_middleware,
            ))
            .layer(session_auth.clone())
            .layer(axum_mw::from_fn(
                crate::command_reconciliation::no_store_response,
            ))
            .layer(axum_mw::from_fn(request_id_middleware));
        let telemetry = operational_telemetry_router(operational_telemetry_state)
            .layer(axum_mw::from_fn_with_state(
                admission_state,
                admission_middleware,
            ))
            .layer(session_auth)
            .layer(axum_mw::from_fn(no_store_response))
            .layer(axum_mw::from_fn(request_id_middleware));
        let local_session_state =
            LocalSessionHttpState::new(local_session_service, clock, verified_tls);
        Ok(Self {
            router: Router::new()
                .merge(health_router(health_state))
                .merge(create_local_session_bootstrap_router(local_session_state))
                .merge(protected)
                .merge(reconciliation)
                .merge(telemetry),
        })
    }
}

fn mount_process_routes<Q: runne_api::ProcessHostPort + 'static>(
    router: Router,
    process_state: ProcessHttpState<Q>,
    advertised: bool,
) -> Router {
    if advertised {
        router.merge(process_router(process_state))
    } else {
        router
    }
}

fn mount_editor_routes<E: runne_api::WorkspaceEditorHostPort + 'static>(
    router: Router,
    state: crate::editors::WorkspaceEditorHttpState<E>,
    advertised: bool,
) -> Router {
    if advertised {
        router.merge(crate::editors::workspace_editor_router(state))
    } else {
        router
    }
}

/// Mounts the protected V2 credential enrollment surface only when its owner
/// supplied the composed host plus per-request admission derivation.
fn mount_provider_credential_enrollment_routes(router: Router, routes: Option<Router>) -> Router {
    match routes {
        Some(routes) => router.merge(routes),
        None => router,
    }
}

#[cfg(test)]
mod process_route_tests {
    use super::*;
    use axum::{body::Body, http::{Request, StatusCode}};
    use runne_api::{ExistingProcessCommand, ProcessCommandContext, ProcessHostError, ProcessOutputPage, ProcessSnapshot, StartProcessCommand};
    use tower::ServiceExt;

    #[derive(Clone)]
    struct Unavailable;
    impl runne_api::ProcessHostPort for Unavailable {
        async fn start_process(&self, _: ProcessCommandContext, _: StartProcessCommand) -> Result<ProcessSnapshot, ProcessHostError> { Err(ProcessHostError::Unavailable) }
        async fn get_process(&self, _: runne_api::ProcessQueryContext, _: runne_domain::id::ProcessId) -> Result<ProcessSnapshot, ProcessHostError> { Err(ProcessHostError::Unavailable) }
        async fn read_process_output(&self, _: runne_api::ProcessQueryContext, _: runne_domain::id::ProcessId, _: u64, _: u16) -> Result<ProcessOutputPage, ProcessHostError> { Err(ProcessHostError::Unavailable) }
        async fn stop_process(&self, _: ProcessCommandContext, _: ExistingProcessCommand) -> Result<ProcessSnapshot, ProcessHostError> { Err(ProcessHostError::Unavailable) }
    }

    #[tokio::test]
    async fn process_routes_are_absent_until_capability_is_advertised() {
        let state = ProcessHttpState::new(Unavailable, runne_api::ApiActor::new("test").unwrap());
        let request = || Request::builder().uri("/v1/processes/018f2e3a-7000-7000-8000-000000000306").extension(crate::error::RequestId::bootstrap_rejection()).body(Body::empty()).unwrap();
        assert_eq!(mount_process_routes(Router::new(), state.clone(), false).oneshot(request()).await.unwrap().status(), StatusCode::NOT_FOUND);
        assert_eq!(mount_process_routes(Router::new(), state, true).oneshot(request()).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
}
