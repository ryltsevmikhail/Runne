use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use runne_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use runne_application::local_session::AuthenticatedRuntimeSession;
use runne_domain::{event::Sensitivity, id::EventLogLineageId};
use std::time::Duration;
use tower::ServiceExt;

fn binding() -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
            ApiPrincipalId::new("local-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000003"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "gocode-ui-client/2",
            [3; 32],
            ordered_capability_digest(&["conversation.create.v1", "conversation.list.v1"]),
        )
        .unwrap(),
        DaemonInstanceId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2]),
        7,
        [5; 16],
        3,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap()
}

#[tokio::test]
async fn session_profile_is_exact_binding_tuple_without_secret_fields() {
    let state = RuntimeProfileHttpState::new(
        "untrusted-handler-copy",
        "untrusted-handler-copy",
        "0.1.0-test",
        &["conversation.create.v1", "conversation.list.v1"],
    )
    .with_provider_statuses(vec![
        ProviderStatusSnapshotV1::new(
            "openai",
            "openai_responses_text_v1",
            "openai-responses-text-v1",
            [0x11; 32],
            runne_api::ProviderReadinessStatusV1::CredentialMissing,
            true,
        )
        .expect("provider status"),
    ]);
    let session = AuthenticatedRuntimeSession {
        binding: binding(),
        expires_at_monotonic: Duration::from_secs(600),
    };
    let mut request = Request::builder()
        .uri("/v1/runtime/profile")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(session);
    let response = runtime_profile_session_router(state)
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(body["profileId"], "gocode-ui-client/2");
    assert_eq!(body["schemaHash"], hex::encode([3; 32]));
    assert_eq!(body["runtimeVersion"], "0.1.0-test");
    assert_eq!(
        body["capabilities"],
        serde_json::json!(["conversation.create.v1", "conversation.list.v1"])
    );
    assert_eq!(body["providerStatuses"][0]["providerId"], "openai");
    assert_eq!(
        body["providerStatuses"][0]["readiness"],
        "credential_missing"
    );
    assert_eq!(
        body["capabilityDigest"],
        hex::encode(ordered_capability_digest(&[
            "conversation.create.v1",
            "conversation.list.v1"
        ]))
    );
    assert_eq!(
        body["authorityId"],
        hex::encode([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1])
    );
    assert_eq!(body["principalId"], "local-owner");
    assert_eq!(
        body["eventLogLineageId"],
        "018f2e3a-7000-7000-8000-000000000003"
    );
    assert_eq!(
        body["daemonInstanceId"],
        "018f2e3a-7000-7000-8000-000000000002"
    );
    assert_eq!(body["launchGeneration"], 7);
    assert_eq!(body["sessionId"], hex::encode([5; 16]));
    assert_eq!(body["authorizationEpoch"], 3);
    assert_eq!(body["sensitivityCeiling"], "internal");
    assert_eq!(body["certificateSha256"], hex::encode([6; 32]));
    for forbidden in [
        "authority",
        "bootstrap",
        "proof",
        "privateKey",
        "replayIntegrityKey",
        "expiresAtMonotonic",
        "token",
        "bearer",
        "credential",
    ] {
        assert!(body.get(forbidden).is_none(), "profile leaked {forbidden}");
    }
}

#[test]
fn ordered_capability_digest_is_domain_separated_and_ordered() {
    assert_eq!(
        hex::encode(ordered_capability_digest(&["a", "b"])),
        "91cdbd7c7dd645123152088fe50eca060dbc7cba7800af8440bab92568f8f89a"
    );
    assert_ne!(
        ordered_capability_digest(&["a", "b"]),
        ordered_capability_digest(&["b", "a"])
    );
}
