use runne_app_core::{
    AppCore, AppCoreError, RuntimeAvailability, RuntimeFailureCode, RuntimeLifecycleStatus,
    RuntimeMode,
};
use runne_runtime_client::{
    GOLDEN_BUNDLE_HASH, REQUIRED_RUNTIME_CAPABILITIES, RuntimeSessionInfo,
    mock_authenticated_runtime_client, mock_protected_authenticated_runtime_client,
};

fn runtime_session(generation: u64, session_id: &str) -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "runne-ui-client/2".to_owned(),
        schema_hash: GOLDEN_BUNDLE_HASH.to_owned(),
        runtime_version: "test".to_owned(),
        capabilities: REQUIRED_RUNTIME_CAPABILITIES
            .iter()
            .map(ToString::to_string)
            .collect(),
        authority_id: "018f2e3a-7000-7000-8000-000000000101".to_owned(),
        principal_id: "local-owner".to_owned(),
        event_log_lineage_id: "018f2e3a-7000-7000-8000-000000000102".to_owned(),
        daemon_instance_id: format!("018f2e3a-7000-7000-8000-{generation:012}"),
        launch_generation: generation,
        session_id: session_id.to_owned(),
        authorization_epoch: 0,
        sensitivity_ceiling: "sensitive".to_owned(),
        certificate_sha256: "11".repeat(32),
        capability_digest: "22".repeat(32),
    }
}

#[test]
fn runtime_connection_states_are_closed_and_only_live_mutates() {
    let states = RuntimeAvailability::ALL;
    let serialized = states
        .iter()
        .map(|state| serde_json::to_string(state).expect("serialize state"))
        .collect::<Vec<_>>();

    assert_eq!(
        serialized,
        [
            "\"unconfigured\"",
            "\"profile_loaded\"",
            "\"peer_verified\"",
            "\"bootstrap_proved\"",
            "\"authenticated\"",
            "\"reconciling\"",
            "\"live\"",
            "\"reconnecting\"",
            "\"incompatible\"",
            "\"revoked\"",
            "\"resync_required\"",
            "\"fatal\"",
        ]
    );
    for state in states {
        assert_eq!(state.allows_mutations(), state == RuntimeAvailability::Live);
    }
}

#[test]
fn runtime_modes_are_closed() {
    let serialized = RuntimeMode::ALL
        .iter()
        .map(|mode| serde_json::to_string(mode).expect("serialize mode"))
        .collect::<Vec<_>>();

    assert_eq!(serialized, ["\"external_local\"", "\"bundled\""]);
}

#[test]
fn runtime_lifecycle_and_failure_codes_are_closed() {
    let lifecycle = RuntimeLifecycleStatus::ALL
        .iter()
        .map(|state| serde_json::to_string(state).expect("serialize lifecycle"))
        .collect::<Vec<_>>();
    assert_eq!(
        lifecycle,
        [
            "\"configuration_required\"",
            "\"starting\"",
            "\"ready\"",
            "\"restarting\"",
            "\"degraded\"",
            "\"failed\"",
            "\"external\"",
        ]
    );

    let failures = RuntimeFailureCode::ALL
        .iter()
        .map(|failure| serde_json::to_string(failure).expect("serialize failure"))
        .collect::<Vec<_>>();
    assert_eq!(
        failures,
        [
            "\"configuration_required\"",
            "\"protected_activation_unavailable\"",
            "\"bundled_executable_unavailable\"",
            "\"bundled_executable_identity_mismatch\"",
            "\"protected_readiness_rejected\"",
            "\"bundled_restart_exhausted\"",
            "\"bundled_shutdown_incomplete\"",
            "\"unsupported_platform_backend\"",
            "\"downgraded_external_profile\"",
        ]
    );
}

#[test]
fn bootstrap_state_serializes_renderer_wire_contract() {
    let state = runne_app_core::BootstrapState {
        theme: "dark".to_string(),
        runtime_mode: RuntimeMode::ExternalLocal,
        runtime: RuntimeAvailability::Reconnecting,
        runtime_lifecycle: RuntimeLifecycleStatus::External,
        runtime_failure: None,
    };

    let serialized = serde_json::to_value(state).expect("serialize bootstrap");

    assert_eq!(
        serialized,
        serde_json::json!({
            "theme": "dark",
            "runtimeMode": "external_local",
            "runtime": "reconnecting",
            "runtimeLifecycle": "external",
            "runtimeFailure": null,
        })
    );
}

#[tokio::test]
async fn external_local_mode_uses_the_configured_profile_path() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_profile(
        &directory.path().join("profile.sqlite3"),
        directory.path().join("missing-runtime-profile.json"),
    )
    .expect("open external-local core");

    assert!(matches!(
        core.connect_runtime().await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    let bootstrap = core.bootstrap().expect("bootstrap");
    assert_eq!(bootstrap.runtime_mode, RuntimeMode::ExternalLocal);
    assert_eq!(bootstrap.runtime, RuntimeAvailability::Reconnecting);
    assert_eq!(
        bootstrap.runtime_lifecycle,
        RuntimeLifecycleStatus::External
    );
    assert_eq!(bootstrap.runtime_failure, None);
}

#[tokio::test]
async fn bundled_mode_fails_closed_without_loading_an_external_profile() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open bundled core");

    assert!(matches!(
        core.connect_runtime().await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    assert_eq!(
        core.bootstrap().expect("bootstrap").runtime_mode,
        RuntimeMode::Bundled
    );
    assert_eq!(
        core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Reconnecting
    );
    assert_eq!(
        core.bootstrap().expect("bootstrap").runtime_lifecycle,
        RuntimeLifecycleStatus::Failed
    );
    assert_eq!(
        core.bootstrap().expect("bootstrap").runtime_failure,
        Some(RuntimeFailureCode::ProtectedActivationUnavailable)
    );
}

#[tokio::test]
async fn bundled_mode_rejects_credential_first_external_client() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open bundled core");
    let client = mock_authenticated_runtime_client(
        "http://127.0.0.1:41001",
        runtime_session(1, "018f2e3a-7000-7000-8000-000000000111"),
    )
    .expect("external client");
    let lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin activation");

    assert!(matches!(
        core.install_bundled_runtime_client(lease, client).await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    let bootstrap = core.bootstrap().expect("bootstrap");
    assert_eq!(bootstrap.runtime, RuntimeAvailability::Incompatible);
    assert_eq!(bootstrap.runtime_lifecycle, RuntimeLifecycleStatus::Failed);
    assert_eq!(
        bootstrap.runtime_failure,
        Some(RuntimeFailureCode::DowngradedExternalProfile)
    );
}

#[tokio::test]
async fn protected_bundled_client_can_rotate_after_restart() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open bundled core");
    let first_lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin first activation");
    let first = mock_protected_authenticated_runtime_client(
        "http://127.0.0.1:41001",
        runtime_session(1, "018f2e3a-7000-7000-8000-000000000111"),
    )
    .expect("first protected client");

    core.install_bundled_runtime_client(first_lease, first)
        .await
        .expect("install first client");
    let ready = core.bootstrap().expect("ready bootstrap");
    assert_eq!(ready.runtime, RuntimeAvailability::Live);
    assert_eq!(ready.runtime_lifecycle, RuntimeLifecycleStatus::Ready);
    assert_eq!(ready.runtime_failure, None);

    let second_lease = core
        .begin_bundled_runtime_restart()
        .await
        .expect("begin restart");
    let restarting = core.bootstrap().expect("restarting bootstrap");
    assert_eq!(restarting.runtime, RuntimeAvailability::Reconnecting);
    assert_eq!(
        restarting.runtime_lifecycle,
        RuntimeLifecycleStatus::Restarting
    );
    assert_eq!(restarting.runtime_failure, None);

    let second = mock_protected_authenticated_runtime_client(
        "http://127.0.0.1:41002",
        runtime_session(2, "018f2e3a-7000-7000-8000-000000000112"),
    )
    .expect("second protected client");
    core.install_bundled_runtime_client(second_lease, second)
        .await
        .expect("install rotated client");
    let recovered = core.bootstrap().expect("recovered bootstrap");
    assert_eq!(recovered.runtime, RuntimeAvailability::Live);
    assert_eq!(recovered.runtime_lifecycle, RuntimeLifecycleStatus::Ready);
}
