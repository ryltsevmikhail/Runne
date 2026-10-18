// Regression tests for terminal failure classification during bundled
// runtime rotations (enrollment renewal fences the prior-epoch client, so
// an Unauthorized from that client must not latch the session terminal).

fn bundled_core() -> AppCore {
    let directory = tempfile::tempdir().expect("temp directory");
    AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open bundled core")
}

#[test]
fn revoked_during_bundled_rotation_keeps_reconnecting() {
    let core = bundled_core();
    core.set_runtime_availability(RuntimeAvailability::Reconnecting)
        .expect("set reconnecting");
    core.set_runtime_lifecycle(RuntimeLifecycleStatus::Restarting)
        .expect("set restarting");
    core.set_runtime_failure(RuntimeAvailability::Revoked)
        .expect("classify failure");
    assert_eq!(
        core.runtime_availability().expect("read availability"),
        RuntimeAvailability::Reconnecting,
        "an Unauthorized from the fenced prior-epoch client during a rotation must stay transient"
    );
    assert_eq!(
        core.runtime_lifecycle().expect("read lifecycle"),
        RuntimeLifecycleStatus::Restarting,
        "the rotation lifecycle must not be downgraded to Failed"
    );
}

#[test]
fn revoked_during_starting_rotation_keeps_reconnecting() {
    let core = bundled_core();
    core.set_runtime_availability(RuntimeAvailability::Reconnecting)
        .expect("set reconnecting");
    core.set_runtime_lifecycle(RuntimeLifecycleStatus::Starting)
        .expect("set starting");
    core.set_runtime_failure(RuntimeAvailability::Revoked)
        .expect("classify failure");
    assert_eq!(
        core.runtime_availability().expect("read availability"),
        RuntimeAvailability::Reconnecting,
    );
}

#[test]
fn revoked_outside_rotation_still_latches_terminal() {
    let core = bundled_core();
    core.set_runtime_availability(RuntimeAvailability::Live)
        .expect("set live");
    core.set_runtime_lifecycle(RuntimeLifecycleStatus::Ready)
        .expect("set ready");
    core.set_runtime_failure(RuntimeAvailability::Revoked)
        .expect("classify failure");
    assert_eq!(
        core.runtime_availability().expect("read availability"),
        RuntimeAvailability::Revoked,
        "a genuine revocation outside any rotation must stay terminal"
    );
    assert_eq!(
        core.runtime_lifecycle().expect("read lifecycle"),
        RuntimeLifecycleStatus::Failed,
    );
}

#[test]
fn incompatible_during_rotation_still_latches_terminal() {
    let core = bundled_core();
    core.set_runtime_lifecycle(RuntimeLifecycleStatus::Restarting)
        .expect("set restarting");
    core.set_runtime_failure(RuntimeAvailability::Incompatible)
        .expect("classify failure");
    assert_eq!(
        core.runtime_availability().expect("read availability"),
        RuntimeAvailability::Incompatible,
        "only the rotation-expected Unauthorized is guarded; other terminal kinds pass through"
    );
}
