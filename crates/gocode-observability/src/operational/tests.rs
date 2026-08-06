use std::{
    sync::{Arc, Barrier},
    thread,
};

use gocode_application::provider::{
    ProviderRecoveryObservationAvailability, ProviderRecoveryObserver,
    ProviderRecoveryObserverError,
};

use super::*;

#[test]
fn records_a_positive_recovery_count() {
    let (registry, observer) = RecoveryObservationRegistry::new();

    observer.observe_recovered_terminal_output().unwrap();

    let snapshot = registry.snapshot_recovery_observation();
    assert!(matches!(
        snapshot.availability(),
        ProviderRecoveryObservationAvailability::Complete
    ));
    assert_eq!(snapshot.observed_count(), Some(1));
    assert_eq!(snapshot.dropped_event_count(), 0);
    assert!(!snapshot.drop_counter_saturated());
}

#[test]
fn registry_is_a_provider_recovery_observer() {
    let (registry, _observer) = RecoveryObservationRegistry::new();

    fn accepts_observer(_observer: &dyn ProviderRecoveryObserver) {}

    accepts_observer(&registry);
    let registry = Arc::new(registry);
    accepts_observer(registry.as_ref());
    registry.observe_recovered_terminal_output().unwrap();

    assert_eq!(
        registry.snapshot_recovery_observation().observed_count(),
        Some(1)
    );
}

#[test]
fn full_closed_and_contended_paths_have_distinct_statuses_and_counts() {
    let (registry, observer) = RecoveryObservationRegistry::new();
    assert_eq!(RECOVERY_OBSERVATION_CHANNEL_CAPACITY_V1, 64);
    for _ in 0..RECOVERY_OBSERVATION_CHANNEL_CAPACITY_V1 {
        assert!(observer.observe_recovered_terminal_output().is_ok());
    }
    assert_eq!(
        observer.observe_recovered_terminal_output(),
        Err(ProviderRecoveryObserverError::Unavailable)
    );
    assert!(matches!(
        registry.snapshot_recovery_observation().availability(),
        ProviderRecoveryObservationAvailability::Truncated
    ));
    assert_eq!(
        registry
            .snapshot_recovery_observation()
            .dropped_event_count(),
        1
    );

    let drain = registry.drain.lock().unwrap();
    assert!(matches!(
        registry.snapshot_recovery_observation().availability(),
        ProviderRecoveryObservationAvailability::Unavailable
    ));
    assert_eq!(
        registry
            .snapshot_recovery_observation()
            .dropped_event_count(),
        1
    );
    drop(drain);

    registry.close();
    assert_eq!(
        observer.observe_recovered_terminal_output(),
        Err(ProviderRecoveryObserverError::Unavailable)
    );
    assert!(matches!(
        registry.snapshot_recovery_observation().availability(),
        ProviderRecoveryObservationAvailability::Unavailable
    ));
    assert_eq!(
        registry
            .snapshot_recovery_observation()
            .dropped_event_count(),
        2
    );
}

#[test]
fn concurrent_close_leaves_snapshot_unavailable_and_rejects_later_observations() {
    let (registry, observer) = RecoveryObservationRegistry::new();
    let registry = Arc::new(registry);
    let start = Arc::new(Barrier::new(2));
    let concurrent_observer = observer.clone();
    let concurrent_start = Arc::clone(&start);
    let concurrent = thread::spawn(move || {
        concurrent_start.wait();
        concurrent_observer.observe_recovered_terminal_output()
    });

    start.wait();
    registry.close();
    let _ = concurrent.join().unwrap();

    assert!(matches!(
        registry.snapshot_recovery_observation().availability(),
        ProviderRecoveryObservationAvailability::Unavailable
    ));
    assert_eq!(
        registry.observe_recovered_terminal_output(),
        Err(ProviderRecoveryObserverError::Unavailable)
    );
    assert_eq!(
        observer.observe_recovered_terminal_output(),
        Err(ProviderRecoveryObserverError::Unavailable)
    );
}

#[test]
fn observed_count_overflow_makes_the_registry_permanently_unavailable() {
    let (registry, observer) = RecoveryObservationRegistry::new();
    registry.set_observed_count_for_test(u64::MAX);
    observer.observe_recovered_terminal_output().unwrap();

    let snapshot = registry.snapshot_recovery_observation();
    assert!(matches!(
        snapshot.availability(),
        ProviderRecoveryObservationAvailability::Unavailable
    ));
    assert_eq!(snapshot.observed_count(), None);
}

#[test]
fn drop_counter_saturates_without_wrapping() {
    let (registry, observer) = RecoveryObservationRegistry::new();
    registry.set_drop_count_for_test(u64::MAX - 1);
    for _ in 0..RECOVERY_OBSERVATION_CHANNEL_CAPACITY_V1 {
        observer.observe_recovered_terminal_output().unwrap();
    }

    assert_eq!(
        observer.observe_recovered_terminal_output(),
        Err(ProviderRecoveryObserverError::Unavailable)
    );
    let snapshot = registry.snapshot_recovery_observation();
    assert!(matches!(
        snapshot.availability(),
        ProviderRecoveryObservationAvailability::Truncated
    ));
    assert_eq!(snapshot.dropped_event_count(), u64::MAX);
    assert!(snapshot.drop_counter_saturated());
}

#[test]
fn concurrent_producers_remain_bounded() {
    let (registry, observer) = RecoveryObservationRegistry::new();
    let observer = Arc::new(observer);
    let workers = (0..128)
        .map(|_| {
            let observer = Arc::clone(&observer);
            thread::spawn(move || observer.observe_recovered_terminal_output())
        })
        .collect::<Vec<_>>();

    let successes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(Result::is_ok)
        .count();
    let snapshot = registry.snapshot_recovery_observation();
    assert_eq!(successes, RECOVERY_OBSERVATION_CHANNEL_CAPACITY_V1);
    assert_eq!(snapshot.observed_count(), Some(64));
    assert_eq!(snapshot.dropped_event_count(), 64);
}

#[test]
fn public_observation_has_no_debug_or_payload_markers() {
    let source = include_str!("../operational.rs");

    for prohibited in [
        ["derive(", "De", "bug"].concat(),
        ["Str", "ing"].concat(),
        ["Hash", "Map"].concat(),
        ["Val", "ue"].concat(),
        ["serde", "_json"].concat(),
    ] {
        assert!(
            !source.contains(&prohibited),
            "forbidden marker: {prohibited}"
        );
    }
}

#[test]
fn observer_failure_and_closed_projection_do_not_reflect_sensitive_markers() {
    let (registry, observer) = RecoveryObservationRegistry::new();
    registry.close();
    let error = observer
        .observe_recovered_terminal_output()
        .expect_err("closed registry must reject the observation");
    let projection = registry.snapshot_recovery_observation();
    assert!(matches!(
        projection.availability(),
        ProviderRecoveryObservationAvailability::Unavailable
    ));
    for marker in [
        "task3-prompt-marker",
        "task3-output-marker",
        "task3-sse-marker",
        "task3-raw-error-marker",
    ] {
        assert!(!format!("{error:?}").contains(marker));
        assert!(!error.to_string().contains(marker));
    }
}

#[test]
fn observability_telemetry_registry_has_no_dynamic_payload_or_diagnostic_projection() {
    let source = include_str!("../operational.rs");
    for forbidden in [
        "serde_json::Value",
        "HashMap",
        "BTreeMap",
        ": String",
        ".to_string()",
        "source: ",
    ] {
        assert!(!source.contains(forbidden), "forbidden marker: {forbidden}");
    }
}
