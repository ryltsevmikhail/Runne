/// Builds the authenticated canonical approval query and decision surface.
pub fn create_router_with_approvals<H>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    approval_state: ApprovalHttpState<H>,
) -> Router
where
    H: ApprovalQueryHostPort + ApprovalCommandHostPort + 'static,
{
    let protected = approval_router(approval_state)
        .layer(axum_mw::from_fn_with_state(admission_state, admission_middleware))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new().merge(health_router(health_state)).merge(protected)
}
