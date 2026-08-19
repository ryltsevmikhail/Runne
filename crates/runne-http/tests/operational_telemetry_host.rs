#[path = "operational_telemetry_host/support.rs"]
mod support;

use runne_http::secure_local_host::LocalRuntimeTlsHostError;
use support::*;

#[tokio::test]
async fn public_typed_bind_is_capability_gated_without_unprotected_mount() {
    let host = bind_with_telemetry(TELEMETRY_CAPABILITIES).await.unwrap();
    assert!(host.local_addr().unwrap().ip().is_loopback());

    assert!(matches!(
        bind_with_telemetry(BASE_CAPABILITIES).await,
        Err(LocalRuntimeTlsHostError::Incompatible)
    ));
}
