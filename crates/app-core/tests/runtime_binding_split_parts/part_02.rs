#[tokio::test]
async fn explicit_shutdown_fence_invalidates_client_and_pending_activation() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open bundled core");
    let first_lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin activation");
    let first_client = mock_protected_authenticated_runtime_client(
        "http://127.0.0.1:41001",
        runtime_session(1, "018f2e3a-7000-7000-8000-000000000111"),
    )
    .expect("protected client");
    core.install_bundled_runtime_client(first_lease, first_client)
        .await
        .expect("install client");

    let pending_lease = core
        .begin_bundled_runtime_restart()
        .await
        .expect("begin pending restart");
    core.fence_bundled_runtime_shutdown()
        .await
        .expect("fence shutdown");

    let stale_client = mock_protected_authenticated_runtime_client(
        "http://127.0.0.1:41002",
        runtime_session(2, "018f2e3a-7000-7000-8000-000000000112"),
    )
    .expect("stale client");
    assert!(matches!(
        core.install_bundled_runtime_client(pending_lease, stale_client)
            .await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    assert!(matches!(
        core.open_project_conversation(1).await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    let bootstrap = core.bootstrap().expect("bootstrap");
    assert_eq!(bootstrap.runtime, RuntimeAvailability::Reconnecting);
    assert_eq!(
        bootstrap.runtime_lifecycle,
        RuntimeLifecycleStatus::Restarting
    );
    assert_eq!(bootstrap.runtime_failure, None);
}

#[tokio::test]
async fn bundled_failures_are_closed_and_do_not_retain_a_live_client() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open bundled core");
    let lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin activation");
    let client = mock_protected_authenticated_runtime_client(
        "http://127.0.0.1:41001",
        runtime_session(1, "018f2e3a-7000-7000-8000-000000000111"),
    )
    .expect("protected client");
    core.install_bundled_runtime_client(lease, client)
        .await
        .expect("install client");

    core.mark_bundled_runtime_degraded(RuntimeFailureCode::ProtectedReadinessRejected)
        .await
        .expect("mark degraded");
    let degraded = core.bootstrap().expect("degraded bootstrap");
    assert_eq!(degraded.runtime, RuntimeAvailability::Reconnecting);
    assert_eq!(degraded.runtime_lifecycle, RuntimeLifecycleStatus::Degraded);
    assert_eq!(
        degraded.runtime_failure,
        Some(RuntimeFailureCode::ProtectedReadinessRejected)
    );

    core.mark_bundled_runtime_failed(RuntimeFailureCode::BundledRestartExhausted)
        .await
        .expect("mark failed");
    let failed = core.bootstrap().expect("failed bootstrap");
    assert_eq!(failed.runtime, RuntimeAvailability::Fatal);
    assert_eq!(failed.runtime_lifecycle, RuntimeLifecycleStatus::Failed);
    assert_eq!(
        failed.runtime_failure,
        Some(RuntimeFailureCode::BundledRestartExhausted)
    );
}

#[tokio::test]
async fn configuration_required_is_a_distinct_bundled_lifecycle() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open bundled core");

    core.mark_bundled_runtime_failed(RuntimeFailureCode::ConfigurationRequired)
        .await
        .expect("mark configuration required");

    let bootstrap = core.bootstrap().expect("configuration bootstrap");
    assert_eq!(bootstrap.runtime, RuntimeAvailability::Unconfigured);
    assert_eq!(
        bootstrap.runtime_lifecycle,
        RuntimeLifecycleStatus::ConfigurationRequired
    );
    assert_eq!(
        bootstrap.runtime_failure,
        Some(RuntimeFailureCode::ConfigurationRequired)
    );
}

#[tokio::test]
async fn stale_activation_completion_cannot_replace_a_newer_restart() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open bundled core");
    let stale_lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin stale activation");
    let current_lease = core
        .begin_bundled_runtime_restart()
        .await
        .expect("begin current activation");
    let stale_client = mock_protected_authenticated_runtime_client(
        "http://127.0.0.1:41001",
        runtime_session(1, "018f2e3a-7000-7000-8000-000000000111"),
    )
    .expect("stale protected client");

    assert!(matches!(
        core.install_bundled_runtime_client(stale_lease, stale_client)
            .await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    let still_restarting = core.bootstrap().expect("restarting bootstrap");
    assert_eq!(
        still_restarting.runtime_lifecycle,
        RuntimeLifecycleStatus::Restarting
    );
    assert_eq!(still_restarting.runtime_failure, None);

    let current_client = mock_protected_authenticated_runtime_client(
        "http://127.0.0.1:41002",
        runtime_session(2, "018f2e3a-7000-7000-8000-000000000112"),
    )
    .expect("current protected client");
    core.install_bundled_runtime_client(current_lease, current_client)
        .await
        .expect("install current client");
    assert_eq!(
        core.bootstrap().expect("ready bootstrap").runtime_lifecycle,
        RuntimeLifecycleStatus::Ready
    );
}

#[tokio::test]
async fn terminal_failure_invalidates_an_in_flight_activation() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("open bundled core");
    let stale_lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin activation");
    core.mark_bundled_runtime_failed(RuntimeFailureCode::BundledRestartExhausted)
        .await
        .expect("mark terminal failure");
    let stale_client = mock_protected_authenticated_runtime_client(
        "http://127.0.0.1:41001",
        runtime_session(1, "018f2e3a-7000-7000-8000-000000000111"),
    )
    .expect("stale protected client");

    assert!(matches!(
        core.install_bundled_runtime_client(stale_lease, stale_client)
            .await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    let failed = core.bootstrap().expect("failed bootstrap");
    assert_eq!(failed.runtime_lifecycle, RuntimeLifecycleStatus::Failed);
    assert_eq!(
        failed.runtime_failure,
        Some(RuntimeFailureCode::BundledRestartExhausted)
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
