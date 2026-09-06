//! Local Engine status endpoint (Plan Task 14).
//!
//! Exposes `GET /local-engine/status` returning the authenticated
//! owner-read snapshot: activation mode, readiness, known
//! installations and the last generation phase. The snapshot source is
//! injected (static for tests, dynamic from the runtime in
//! production).

use axum::{Json, Router, http::StatusCode, routing::get};
use runne_api::local_engine::LocalEngineStatusSnapshotV1;

/// Read-only source of the current snapshot.
#[derive(Clone)]
pub struct LocalEngineState {
    snapshot: Option<LocalEngineStatusSnapshotV1>,
}

impl LocalEngineState {
    /// Composes the state from an already validated snapshot.
    pub fn new(snapshot: Option<LocalEngineStatusSnapshotV1>) -> Self {
        Self { snapshot }
    }
}

/// Build an Axum `Router` serving the local engine status endpoint.
pub fn local_engine_router(state: LocalEngineState) -> Router {
    Router::new()
        .route("/local-engine/status", get(local_engine_status_handler))
        .with_state(state)
}

/// Handler for `GET /local-engine/status`.
async fn local_engine_status_handler(
    axum::extract::State(state): axum::extract::State<LocalEngineState>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.snapshot {
        Some(snapshot) => {
            let value = serde_json::to_value(&snapshot).unwrap_or(serde_json::Value::Null);
            (StatusCode::OK, Json(value))
        }
        None => (
            StatusCode::OK,
            Json(serde_json::json!({
                "activationMode": "",
                "readiness": "not_selected",
                "installations": [],
                "generation": null,
            })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use runne_api::local_engine::{
        LocalEngineGenerationPhaseV1, LocalEngineReadinessV1, LocalEngineStatusSnapshotV1,
        LocalInstallationSnapshotV1,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn status_route_serves_injected_snapshot() {
        let installation = LocalInstallationSnapshotV1::new(
            "m1",
            "r1",
            "sha256:a3d27b1a556d63979122c0aa64b44c9f9d69701323b3fa4333839bcd399ee61e",
            "2026-09-05-r1",
            0,
        )
        .expect("installation");
        let snapshot = LocalEngineStatusSnapshotV1::new(
            "local_engine_text_v1",
            LocalEngineReadinessV1::Ready,
            vec![installation],
            Some(LocalEngineGenerationPhaseV1::Idle),
        )
        .expect("snapshot");
        let app = local_engine_router(LocalEngineState::new(Some(snapshot)));
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/local-engine/status")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            value["readiness"],
            serde_json::Value::String("ready".into())
        );
        assert_eq!(value["installations"][0]["modelId"], "m1");
    }

    #[tokio::test]
    async fn status_route_defaults_to_explicit_not_selected() {
        let app = local_engine_router(LocalEngineState::new(None));
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/local-engine/status")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            value["readiness"],
            serde_json::Value::String("not_selected".into())
        );
        assert_eq!(
            value["activationMode"],
            serde_json::Value::String(String::new())
        );
    }
}
