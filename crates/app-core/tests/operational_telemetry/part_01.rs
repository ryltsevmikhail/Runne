#[test]
fn transition_serializes_current_sequence_and_event_before_try_send() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open core");
    core.record_host_lifecycle(RuntimeLifecycleStatus::Restarting, None, Some(8), 10)
        .expect("record transition");

    let telemetry = core
        .operational_telemetry_snapshot(10)
        .expect("telemetry snapshot");
    assert_eq!(telemetry.host_lifecycle().last_allocated_sequence(), Some(1));
    assert_eq!(telemetry.host_lifecycle().events().expect("events")[0].sequence(), 1);
}

#[test]
fn external_mode_has_no_restart_ordinal() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::ExternalLocal,
    )
    .expect("open core");
    core.record_host_lifecycle(RuntimeLifecycleStatus::External, None, None, 10)
        .expect("record external lifecycle");

    let telemetry = core
        .operational_telemetry_snapshot(10)
        .expect("telemetry snapshot");
    assert_eq!(
        telemetry.host_lifecycle().current().expect("current lifecycle").restart_ordinal(),
        None
    );
}

#[test]
fn duplicate_tuple_does_not_allocate_an_event() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open(&directory.path().join("profile.sqlite3")).expect("open core");
    core.record_host_lifecycle(RuntimeLifecycleStatus::External, None, None, 10)
        .expect("record duplicate external lifecycle");

    let snapshot = core.operational_telemetry_snapshot(10).expect("telemetry snapshot");
    assert_eq!(snapshot.host_lifecycle().last_allocated_sequence(), None);
    assert_eq!(snapshot.host_lifecycle().events().expect("events").len(), 0);
}

#[test]
fn full_channel_and_ring_eviction_have_independent_drop_counts() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open core");
    for generation in 1..=65 {
        core.record_host_lifecycle(RuntimeLifecycleStatus::Degraded, None, Some(generation), generation)
            .expect("record transition");
    }
    let first = core.operational_telemetry_snapshot(100).expect("first snapshot");
    assert_eq!(first.host_lifecycle().events().expect("events").len(), 64);
    assert_eq!(first.host_lifecycle().producer_dropped_event_count(), 1);
    assert!(first.host_lifecycle().event_status() == HostLifecycleEventStatusV1::TruncatedSinceAppCoreStart);

    for generation in 66..=129 {
        core.record_host_lifecycle(RuntimeLifecycleStatus::Degraded, None, Some(generation), generation)
            .expect("record transition");
    }
    let second = core.operational_telemetry_snapshot(200).expect("second snapshot");
    assert_eq!(second.host_lifecycle().evicted_event_count(), 64);
    assert_eq!(second.host_lifecycle().producer_dropped_event_count(), 1);
    assert_eq!(second.host_lifecycle().events().expect("events")[0].sequence(), 66);
}

#[test]
fn restart_ordinals_advance_once_per_distinct_episode() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open core");
    for (lifecycle, generation, time) in [
        (RuntimeLifecycleStatus::Restarting, 1, 1),
        (RuntimeLifecycleStatus::Restarting, 1, 2),
        (RuntimeLifecycleStatus::Starting, 1, 3),
        (RuntimeLifecycleStatus::Restarting, 2, 4),
    ] {
        core.record_host_lifecycle(lifecycle, None, Some(generation), time).expect("record lifecycle");
    }
    let events = core.operational_telemetry_snapshot(4).expect("telemetry snapshot")
        .host_lifecycle().events().expect("events").clone();
    assert_eq!(events[0].restart_ordinal(), Some(1));
    assert_eq!(events[1].restart_ordinal(), Some(1));
    assert_eq!(events[2].restart_ordinal(), Some(2));
}

#[test]
fn lifecycle_failure_and_mode_invariants_reject_invalid_tuples() {
    let directory = tempfile::tempdir().expect("temp directory");
    let bundled = AppCore::open_with_runtime_mode(
        &directory.path().join("bundled.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open bundled core");
    assert!(bundled.record_host_lifecycle(RuntimeLifecycleStatus::ConfigurationRequired, None, Some(0), 1).is_err());
    assert!(bundled.record_host_lifecycle(RuntimeLifecycleStatus::Ready, None, None, 1).is_err());
    assert!(bundled.record_host_lifecycle(
        RuntimeLifecycleStatus::Starting,
        Some(RuntimeFailureCode::ProtectedActivationUnavailable),
        Some(0),
        1,
    ).is_err());
    bundled.record_host_lifecycle(
        RuntimeLifecycleStatus::ConfigurationRequired,
        Some(RuntimeFailureCode::ConfigurationRequired),
        Some(0),
        1,
    ).expect("matching configuration failure");

    let external = AppCore::open(&directory.path().join("external.sqlite3")).expect("open external core");
    assert!(external.record_host_lifecycle(RuntimeLifecycleStatus::Ready, None, Some(1), 1).is_err());
}
