/// Builds the production read-only command reconciliation surface.
pub fn create_router_with_command_reconciliation<H>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    reconciliation_state: CommandReconciliationHttpState<H>,
) -> Router
where
    H: runne_api::CommandReconciliationHostPort + 'static,
{
    let protected = command_reconciliation_router(reconciliation_state)
        .layer(axum_mw::from_fn_with_state(
            admission_state,
            admission_middleware,
        ))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(
            crate::command_reconciliation::no_store_response,
        ))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new()
        .merge(health_router(health_state))
        .merge(protected)
}
