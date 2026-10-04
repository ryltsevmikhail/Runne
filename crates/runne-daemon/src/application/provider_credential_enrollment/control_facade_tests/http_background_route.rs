#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use std::sync::Arc;

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use axum::{
    Extension,
    body::Body,
    http::{Request, StatusCode},
};
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use runne_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use runne_application::local_session::AuthenticatedRuntimeSession;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use runne_domain::{event::Sensitivity, id::EventLogLineageId};
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use tower::ServiceExt;

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use super::super::test_modules::protected_session_tests::control;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use crate::application::provider_credential_enrollment::ProtectedEnrollmentSessionFacts;

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
#[tokio::test]
async fn background_scoped_status_reads_only_the_selected_control() {
    let (background, facts, _approval_root) = activated_background_control();
    let (primary, _) = control();
    let authenticated = authenticated_session(&facts);

    let background_router = background
        .http_enrollment_router_for_provider("openai-background", Arc::new(|| 1_800_000_000))
        .layer(Extension(authenticated.clone()));
    let response = background_router
        .oneshot(
            Request::get("/v2/providers/openai-background/credential-enrollment")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "selected realm status response: {}",
        String::from_utf8_lossy(&body)
    );
    let projection: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(projection["providerId"], "openai-background");

    let cold_primary_router = primary
        .http_enrollment_router_for_provider("openai-background", Arc::new(|| 1_800_000_000))
        .layer(Extension(authenticated));
    let cold = cold_primary_router
        .oneshot(
            Request::get("/v2/providers/openai-background/credential-enrollment")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cold.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
#[tokio::test]
async fn background_http_begin_and_verify_remain_native_only() {
    let (background, facts, _approval_root) = activated_background_control();
    let router = background
        .http_enrollment_router_for_provider("openai-background", Arc::new(|| 1_800_000_000))
        .layer(Extension(authenticated_session(&facts)));

    for (path, body) in [
        (
            "/v2/providers/openai-background/credential-enrollment/begin",
            r#"{"action":"pair","provider":"openai-background","expectedLifecycleRevision":1,"commandIdentity":"018f2e3a-7000-7000-8000-000000000003","idempotencyKey":"background-direct-begin","nativeIntentId":"native-intent"}"#,
        ),
        (
            "/v2/providers/openai-background/credential-enrollment/verify",
            r#"{"provider":"openai-background","expectedLifecycleRevision":1,"verificationKind":"local","commandIdentity":"018f2e3a-7000-7000-8000-000000000004","nativeIntentId":"native-intent"}"#,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "background {path} requires the verified native enrollment exchange"
        );
    }
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
fn activated_background_control() -> (
    Arc<crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl>,
    ProtectedEnrollmentSessionFacts,
    tempfile::TempDir,
){
    use runne_api::provider_credential_enrollment::linux_activation_policy::{
        LinuxEnrollmentActivationRecord, LinuxEnrollmentScope, LinuxInstallationFacts,
    };
    use std::os::unix::fs::PermissionsExt as _;

    let (mut control, _) = control();
    let (owned, _, _) = crate::protected_activation::test_enrollment_owned_and_sessions();
    let runtime_authority = *owned.stable().authority_id();
    Arc::get_mut(&mut control).unwrap().runtime_authority = runtime_authority;
    let facts = ProtectedEnrollmentSessionFacts::from_owned(&owned, runtime_authority, 10).unwrap();
    let root = tempfile::tempdir().unwrap();
    let install = LinuxInstallationFacts {
        runtime_root_digest: [21; 32],
        desktop_image_digest: [22; 32],
        writer_image_digest: [23; 32],
        daemon_image_digest: [24; 32],
        runtime_authority_id: runtime_authority,
        machine_id_digest: [25; 32],
    };
    control
        .install_linux_preadmission(&owned, root.path(), install)
        .unwrap();
    let approval = LinuxEnrollmentActivationRecord {
        provider_scope: LinuxEnrollmentScope::Catalog,
        runtime_root_digest: install.runtime_root_digest,
        desktop_image_digest: install.desktop_image_digest,
        writer_image_digest: install.writer_image_digest,
        daemon_image_digest: install.daemon_image_digest,
        runtime_authority_id: install.runtime_authority_id,
        machine_id_digest: install.machine_id_digest,
        approved_at_unix_millis: 1,
    };
    let path = root.path().join(
        runne_api::provider_credential_enrollment::linux_activation_policy::ACTIVATION_RECORD_FILE,
    );
    std::fs::write(&path, approval.to_config_json()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    control.publish_http_facts(facts.clone()).unwrap();
    (control, facts, root)
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
fn authenticated_session(facts: &ProtectedEnrollmentSessionFacts) -> AuthenticatedRuntimeSession {
    use std::time::Duration;

    let stable = StableRuntimeBinding::new(
        facts.launch_authority,
        ApiPrincipalId::new("protected-route-test").unwrap(),
        "018f2e3a-7000-7000-8000-000000000003"
            .parse::<EventLogLineageId>()
            .unwrap(),
        "gocode-ui-client/2",
        facts.installation,
        facts.release,
    )
    .unwrap();
    let binding = RuntimeSessionBinding::new(
        stable,
        DaemonInstanceId::from_bytes(facts.daemon),
        facts.launch_generation,
        facts.session,
        facts.supervisor_generation,
        Sensitivity::Internal,
        facts.tauri_peer,
    )
    .unwrap();
    AuthenticatedRuntimeSession {
        binding,
        expires_at_monotonic: Duration::from_secs(600),
    }
}
