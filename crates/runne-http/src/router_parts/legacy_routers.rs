/// Builds the canonical surface plus the pinned OpenCode V1 compatibility
/// routes under the same protection contour.
pub fn create_router_with_opencode<T, O>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<T>,
    opencode_state: OpenCodeSessionState<O>,
) -> Router
where
    T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
    O: runne_opencode_compat::SessionV1HostPort + 'static,
{
    let protected = Router::new()
        .merge(task_run_router(task_run_state))
        .merge(opencode_session_router(opencode_state))
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

fn protected_task_run_router<H>(
    token: [u8; 32],
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<H>,
) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    task_run_router(task_run_state)
        .layer(axum_mw::from_fn_with_state(
            admission_state,
            admission_middleware,
        ))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware))
}
