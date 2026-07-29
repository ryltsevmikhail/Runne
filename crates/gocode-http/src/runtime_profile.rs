//! Authenticated exact runtime profile query.

use axum::{Json, Router, routing::get};
use serde::Serialize;

/// Immutable exact profile advertised by the running daemon.
#[derive(Clone)]
pub struct RuntimeProfileHttpState {
    profile_id: &'static str,
    schema_hash: &'static str,
    runtime_version: &'static str,
    capabilities: &'static [&'static str],
}

impl RuntimeProfileHttpState {
    /// Creates the built-in profile response.
    #[must_use]
    pub const fn new(
        profile_id: &'static str,
        schema_hash: &'static str,
        runtime_version: &'static str,
        capabilities: &'static [&'static str],
    ) -> Self {
        Self {
            profile_id,
            schema_hash,
            runtime_version,
            capabilities,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeProfileWire {
    profile_id: &'static str,
    schema_hash: &'static str,
    runtime_version: &'static str,
    capabilities: &'static [&'static str],
}

/// Builds the profile query route. Authentication is applied by the parent
/// protected router.
pub fn runtime_profile_router(state: RuntimeProfileHttpState) -> Router {
    Router::new().route(
        "/v1/runtime/profile",
        get(move || async move {
            Json(RuntimeProfileWire {
                profile_id: state.profile_id,
                schema_hash: state.schema_hash,
                runtime_version: state.runtime_version,
                capabilities: state.capabilities,
            })
        }),
    )
}
