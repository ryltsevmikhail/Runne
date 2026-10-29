//! TLS-only HTTP bootstrap endpoints for local runtime sessions.

#![allow(dead_code)] // Used by the crate-owned TLS serving boundary in Task 4B.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router, extract::DefaultBodyLimit, http::StatusCode, response::Response, routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use runne_application::local_session::{BootstrapClock, LocalSessionService};

use crate::error::{RequestId, canonical_error_response};

#[path = "local_session/bootstrap_v3_http.rs"]
mod bootstrap_v3_http;
mod close;
use bootstrap_v3_http::{authenticate, challenge};

const MAX_LOCAL_SESSION_BODY_BYTES: usize = 8 * 1024;

/// State for bootstrap routes, restricted to an already verified TLS listener.
#[derive(Clone)]
pub(crate) struct LocalSessionHttpState {
    service: Arc<Mutex<LocalSessionService>>,
    clock: Arc<dyn Fn() -> Option<BootstrapClock> + Send + Sync>,
    _verified_tls: VerifiedLocalTls,
}

/// Capability minted only by verified local-TLS listener composition.
#[derive(Clone)]
pub(crate) struct VerifiedLocalTls(());

impl VerifiedLocalTls {
    #[allow(dead_code)] // Constructed by the verified listener in Task 4.
    pub(crate) const fn from_verified_listener() -> Self {
        Self(())
    }
}

impl LocalSessionHttpState {
    /// Creates bootstrap state after the pinned local TLS listener has verified its identity.
    #[allow(dead_code)] // Constructed by the verified listener in Task 4.
    pub(crate) fn new(
        service: Arc<Mutex<LocalSessionService>>,
        monotonic_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
        verified_tls: VerifiedLocalTls,
    ) -> Self {
        let clock = Arc::new(move || {
            let micros = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_micros();
            Some(BootstrapClock::new(
                i64::try_from(micros).ok()?,
                monotonic_clock(),
            ))
        });
        Self {
            service,
            clock,
            _verified_tls: verified_tls,
        }
    }

    /// Shares the bounded service with a composable session-auth layer.
    pub(crate) fn service(&self) -> Arc<Mutex<LocalSessionService>> {
        self.service.clone()
    }

    #[cfg(test)]
    fn with_clock(
        service: Arc<Mutex<LocalSessionService>>,
        clock: Arc<dyn Fn() -> Option<BootstrapClock> + Send + Sync>,
        verified_tls: VerifiedLocalTls,
    ) -> Self {
        Self {
            service,
            clock,
            _verified_tls: verified_tls,
        }
    }
}

/// Builds bounded bootstrap and authenticated session-release endpoints. The caller must mount this router only on TLS.
pub(crate) fn local_session_router(state: LocalSessionHttpState) -> Router {
    Router::new()
        .route("/v1/local-session/challenges", post(challenge))
        .route("/v1/local-session/authenticate", post(authenticate))
        .route("/v1/local-session/close", post(close::close))
        .layer(DefaultBodyLimit::max(MAX_LOCAL_SESSION_BODY_BYTES))
        .with_state(state)
}

fn decode_32(value: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()
}
fn decode_16(value: &str) -> Option<[u8; 16]> {
    URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()
}
fn rejected() -> Response {
    canonical_error_response(
        StatusCode::UNAUTHORIZED,
        "BOOTSTRAP_REJECTED",
        &RequestId::bootstrap_rejection(),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    include!("local_session/tests.rs");
    mod close_tests {
        include!("local_session/close_tests.rs");
    }
}
