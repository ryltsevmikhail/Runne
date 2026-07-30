use gocode_app_core::{AppCore, AppCoreError, RuntimeAvailability, RuntimeMode};

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
}

#[test]
fn runtime_connection_cannot_skip_authenticated_bootstrap_stages() {
    assert!(
        RuntimeAvailability::Unconfigured
            .transition_to(RuntimeAvailability::Authenticated)
            .is_err()
    );
    assert!(
        RuntimeAvailability::ProfileLoaded
            .transition_to(RuntimeAvailability::BootstrapProved)
            .is_err()
    );
    assert!(
        RuntimeAvailability::PeerVerified
            .transition_to(RuntimeAvailability::Authenticated)
            .is_err()
    );

    let state = RuntimeAvailability::Unconfigured
        .transition_to(RuntimeAvailability::ProfileLoaded)
        .expect("profile loaded")
        .transition_to(RuntimeAvailability::PeerVerified)
        .expect("peer verified")
        .transition_to(RuntimeAvailability::BootstrapProved)
        .expect("bootstrap proved")
        .transition_to(RuntimeAvailability::Authenticated)
        .expect("authenticated")
        .transition_to(RuntimeAvailability::Reconciling)
        .expect("reconciling")
        .transition_to(RuntimeAvailability::Live)
        .expect("live");
    assert_eq!(state, RuntimeAvailability::Live);
}
