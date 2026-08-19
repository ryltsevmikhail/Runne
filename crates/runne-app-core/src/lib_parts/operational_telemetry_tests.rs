use super::*;

#[test]
fn closed_pipeline_counts_a_saturated_producer_drop() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open core");
    core.lifecycle_producer_drops
        .store(u64::MAX - 1, Ordering::Release);
    core.lifecycle_producer_drop_saturated
        .store(false, Ordering::Release);
    core.lifecycle_event_pipeline
        .lock()
        .expect("pipeline")
        .receiver
        .close();

    core.record_host_lifecycle(RuntimeLifecycleStatus::Degraded, None, Some(1), 1)
        .expect("canonical transition");
    assert_eq!(
        core.host_lifecycle
            .read()
            .expect("lifecycle state")
            .current()
            .expect("internal current lifecycle")
            .runtime_launch_generation(),
        Some(1)
    );

    let snapshot = core
        .operational_telemetry_snapshot(1)
        .expect("telemetry snapshot");
    let lifecycle = snapshot.host_lifecycle();
    assert_eq!(lifecycle.producer_dropped_event_count(), u64::MAX);
    assert!(lifecycle.producer_drop_counter_saturated());
    assert!(lifecycle.event_status() == HostLifecycleEventStatusV1::Unavailable);
}

#[test]
fn restart_ordinal_overflow_preserves_internal_current_and_hides_projection() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open core");
    {
        let mut state = core.host_lifecycle.write().expect("lifecycle state");
        state.restart_ordinal = Some(u64::MAX);
        state.current = Some(HostLifecycleCurrentV1 {
            lifecycle: RuntimeLifecycleStatus::Ready,
            failure: None,
            restart_ordinal: Some(u64::MAX),
            runtime_launch_generation: Some(1),
            observed_at_unix_seconds: 1,
        });
    }

    core.record_host_lifecycle(RuntimeLifecycleStatus::Restarting, None, Some(2), 2)
        .expect("canonical transition");
    {
        let state = core.host_lifecycle.read().expect("lifecycle state");
        let current = state.current().expect("current lifecycle");
        assert_eq!(current.lifecycle(), RuntimeLifecycleStatus::Restarting);
        assert_eq!(current.restart_ordinal(), Some(u64::MAX));
        drop(state);
    }

    let first_snapshot = core
        .operational_telemetry_snapshot(2)
        .expect("first telemetry snapshot");
    let first_lifecycle = first_snapshot.host_lifecycle();
    assert!(
        first_lifecycle.meta().completeness() == TelemetryCompletenessV1::Unavailable
    );
    assert!(first_lifecycle.current().is_none());
    assert!(first_lifecycle.events().is_none());

    core.record_host_lifecycle(RuntimeLifecycleStatus::Degraded, None, Some(3), 3)
        .expect("later canonical transition");
    let state = core.host_lifecycle.read().expect("later lifecycle state");
    let current = state.current().expect("later current lifecycle");
    assert_eq!(current.lifecycle(), RuntimeLifecycleStatus::Degraded);
    assert_eq!(current.restart_ordinal(), Some(u64::MAX));
    drop(state);

    let snapshot = core
        .operational_telemetry_snapshot(3)
        .expect("later telemetry snapshot");
    let lifecycle = snapshot.host_lifecycle();
    assert!(lifecycle.meta().completeness() == TelemetryCompletenessV1::Unavailable);
    assert!(lifecycle.current().is_none());
    assert!(lifecycle.events().is_none());
}

#[test]
fn sequence_overflow_keeps_current_but_disables_telemetry() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open core");
    core.host_lifecycle
        .write()
        .expect("lifecycle state")
        .last_allocated_sequence = Some(u64::MAX);

    core.record_host_lifecycle(RuntimeLifecycleStatus::Degraded, None, Some(1), 1)
        .expect("canonical transition");

    let snapshot = core
        .operational_telemetry_snapshot(1)
        .expect("telemetry snapshot");
    let lifecycle = snapshot.host_lifecycle();
    assert_eq!(lifecycle.last_allocated_sequence(), Some(u64::MAX));
    assert!(lifecycle.meta().completeness() == TelemetryCompletenessV1::Unavailable);
    assert!(lifecycle.current().is_none());
    assert!(lifecycle.events().is_none());
}

#[test]
fn contended_pipeline_leaves_current_available() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open core");
    core.record_host_lifecycle(RuntimeLifecycleStatus::Degraded, None, Some(1), 1)
        .expect("record transition");

    let pipeline = core.lifecycle_event_pipeline.lock().expect("pipeline");
    let snapshot = core
        .operational_telemetry_snapshot(2)
        .expect("contended snapshot");
    drop(pipeline);
    assert!(snapshot.host_lifecycle().events().is_none());
    assert!(snapshot.host_lifecycle().current().is_some());
}
