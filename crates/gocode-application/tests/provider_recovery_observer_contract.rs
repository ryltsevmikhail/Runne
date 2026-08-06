use gocode_application::provider::{
    ProviderOperationalTelemetryScope, ProviderOperationalTelemetrySourceError,
    ProviderRecoveryObserver, ProviderRecoveryObserverError,
};

#[test]
fn recovery_observer_is_closed_and_receives_only_successful_recovery_signal() {
    struct Observer;

    impl ProviderRecoveryObserver for Observer {
        fn observe_recovered_terminal_output(&self) -> Result<(), ProviderRecoveryObserverError> {
            Ok(())
        }
    }

    let scope = ProviderOperationalTelemetryScope::new([1; 16], 1, 7, 7, [2; 32], 100).unwrap();

    assert_eq!(scope.launch_generation(), 7);
    assert!(Observer.observe_recovered_terminal_output().is_ok());
}

#[test]
fn telemetry_scope_rejects_zero_runtime_authority_id() {
    assert_invalid_scope(ProviderOperationalTelemetryScope::new(
        [0; 16], 1, 7, 7, [2; 32], 100,
    ));
}

#[test]
fn telemetry_scope_rejects_zero_profile_digest() {
    assert_invalid_scope(ProviderOperationalTelemetryScope::new(
        [1; 16], 1, 7, 7, [0; 32], 100,
    ));
}

#[test]
fn telemetry_scope_rejects_zero_database_generation() {
    assert_invalid_scope(ProviderOperationalTelemetryScope::new(
        [1; 16], 0, 7, 7, [2; 32], 100,
    ));
}

#[test]
fn telemetry_scope_rejects_zero_launch_generation() {
    assert_invalid_scope(ProviderOperationalTelemetryScope::new(
        [1; 16], 1, 0, 7, [2; 32], 100,
    ));
}

#[test]
fn telemetry_scope_rejects_zero_fencing_token() {
    assert_invalid_scope(ProviderOperationalTelemetryScope::new(
        [1; 16], 1, 7, 0, [2; 32], 100,
    ));
}

fn assert_invalid_scope(
    result: Result<ProviderOperationalTelemetryScope, ProviderOperationalTelemetrySourceError>,
) {
    assert_eq!(
        result.err(),
        Some(ProviderOperationalTelemetrySourceError::Unavailable)
    );
}
