//! Admission middleware gating all requests on `RecoveryState`.
//!
//! When the daemon is in `IntegrityBlocked` or `ShuttingDown` the
//! middleware returns `503 Service Unavailable` for every non-health
//! request. `Ready` and `RecoveryBlocked` are allowed through.
//!
//! The health endpoint should be served on a separate router that
//! does *not* include this middleware.

use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use std::sync::{Arc, RwLock};

/// Cloneable admission state shared across requests.
#[derive(Clone)]
pub struct AdmissionState {
    state: Arc<RwLock<super::health::RecoveryState>>,
}

impl AdmissionState {
    /// Create a new `AdmissionState` with the given initial recovery state.
    pub fn new(initial: super::health::RecoveryState) -> Self {
        Self {
            state: Arc::new(RwLock::new(initial)),
        }
    }

    /// Atomically update the current recovery state.
    pub fn update(&self, new_state: super::health::RecoveryState) {
        *self.state.write().unwrap() = new_state;
    }

    /// Return a snapshot of the current recovery state.
    pub fn current(&self) -> super::health::RecoveryState {
        self.state.read().unwrap().clone()
    }
}

/// Axum middleware that gates requests on the current `RecoveryState`.
pub async fn admission_middleware(
    axum::extract::State(state): axum::extract::State<AdmissionState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match state.current() {
        super::health::RecoveryState::Ready | super::health::RecoveryState::RecoveryBlocked => {
            Ok(next.run(request).await)
        }
        _ => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}
