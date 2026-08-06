use std::sync::Arc;

use gocode_api::{
    OperationalTelemetryQueryErrorV1, OperationalTelemetryQueryPort,
    RuntimeOperationalTelemetrySnapshotV1,
};
use gocode_http::operational_telemetry::OperationalTelemetryHttpState;

#[path = "operational_telemetry_host/support.rs"]
mod tls_support;

struct UnavailableQuery;

impl OperationalTelemetryQueryPort for UnavailableQuery {
    fn query_operational_telemetry(
        &self,
    ) -> Result<RuntimeOperationalTelemetrySnapshotV1, OperationalTelemetryQueryErrorV1> {
        Err(OperationalTelemetryQueryErrorV1::Unavailable)
    }
}

#[test]
fn public_surface_exposes_typed_state_without_router_mount() {
    let state = OperationalTelemetryHttpState::new(Arc::new(UnavailableQuery));
    drop(state);
}

#[tokio::test]
async fn public_tls_telemetry_bind_is_capability_gated_in_the_route_target() {
    let host = tls_support::bind_with_telemetry(tls_support::TELEMETRY_CAPABILITIES)
        .await
        .unwrap();
    assert!(host.local_addr().unwrap().ip().is_loopback());
    assert!(
        tls_support::bind_with_telemetry(tls_support::BASE_CAPABILITIES)
            .await
            .is_err()
    );
}

#[test]
fn external_route_target_enforces_no_cors_telemetry_boundary_source_shape() {
    let source = include_str!("../src/operational_telemetry.rs");
    for forbidden in [
        "Access-Control-Allow-Origin",
        "serde_json::Value",
        "pub fn operational_telemetry_router",
        "tracing::",
    ] {
        assert!(!source.contains(forbidden), "contains {forbidden}");
    }
}
