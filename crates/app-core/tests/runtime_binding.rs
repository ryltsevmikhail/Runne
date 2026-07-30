use gocode_app_core::RuntimeAvailability;

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
