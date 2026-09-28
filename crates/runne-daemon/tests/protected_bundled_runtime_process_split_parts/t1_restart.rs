use super::*;

pub(super) struct RevokedRestartContext<'a> {
    pub executable: &'a owner_private::ControlledExecutable,
    pub runtime_root: &'a std::path::Path,
    pub desktop_db: &'a std::path::Path,
    pub profile_key: [u8; 32],
    pub secure: Arc<runne_secure_store::test_support::DeterministicSecureStore>,
    pub project_directory: &'a std::path::Path,
    pub conversation_id: runne_runtime_client::CanonicalId,
    pub provider_root: &'a std::path::Path,
    pub daemon_database: &'a std::path::Path,
    pub revoked_revision: u64,
    pub scanner: &'a secret_scan::SecretScanner,
}

pub(super) async fn assert_revoked_restart(context: RevokedRestartContext<'_>) {
    let RevokedRestartContext {
        executable,
        runtime_root,
        desktop_db,
        profile_key,
        secure,
        project_directory,
        conversation_id,
        provider_root,
        daemon_database,
        revoked_revision,
        scanner,
    } = context;
    // The restarted runtime root lives inside the same owner-private fixture
    // root as the initial launch, so its parent hosts the fixture bus socket.
    let session_bus_socket = super::t1_support::fixture_session_bus(
        runtime_root.parent().expect("owner-private fixture root"),
        "session-bus-restart.sock",
    );
    let spec = ProtectedBundledRuntimeLaunchSpec::new(executable.path(), runtime_root)
        .expect("protected restart launch spec")
        .with_openai_provider_activation()
        .with_validated_session_bus_address(&session_bus_socket)
        .expect("fixture session bus address");
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    supervisor.start().expect("protected runtime restart");
    let client = supervisor
        .take_runtime_profile()
        .expect("restarted protected profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("restarted authenticated runtime client");
    supervisor
        .record_client_ready(&client)
        .expect("restarted protected readiness");
    let current_trust = super::t1_support::current_project_trust(daemon_database);
    assert_eq!(
        current_trust.status,
        runne_application::project_trust::ProjectTrustStatus::Untrusted
    );
    assert_eq!(current_trust.revision, revoked_revision);
    let scope = runne_runtime_client::ReplayScope::new(
        runne_runtime_client::ReplayAggregateKind::Conversation,
        conversation_id,
    );
    let replay_error = client
        .catch_up(scope, None, |_| Ok::<_, ()>(()))
        .await
        .err()
        .unwrap_or_else(|| panic!("restarted replay must reject the revoked project"));
    assert_eq!(
        replay_error.kind(),
        runne_runtime_client::ReplayClientErrorKind::AuthorizationRevoked
    );
    super::assert_tree_absent(
        "protected T1 daemon sinks after restarted replay denial",
        &provider_root.join("runne-daemon"),
        scanner,
    );
    super::t1_support::assert_profile_sqlite_absent(
        scanner,
        "AppCore profile after restarted replay denial",
        desktop_db,
    );
    let core = AppCore::open_bundled_anchored(desktop_db, secure, profile_key)
        .expect("reopen AppCore after daemon restart");
    let lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin restarted AppCore runtime install");
    core.install_bundled_runtime_client(lease, client)
        .await
        .expect("install restarted authenticated client");
    let project = core
        .open_local_project(project_directory)
        .expect("reopen project");
    let error = core
        .send_project_message(project, "restart dispatch denied")
        .await
        .expect_err("restart dispatch must reject the revoked project");
    assert!(matches!(
        error,
        runne_app_core::AppCoreError::RuntimeRevoked
    ));
    assert_eq!(
        std::fs::read_to_string(provider_root.join("fixture-provider-request-count"))
            .expect("provider request count after restart"),
        "1",
        "revoked restart cannot dispatch another provider request"
    );
    assert_eq!(
        std::fs::read_to_string(provider_root.join("fixture-provider-connection-count"))
            .expect("provider connection count after restart"),
        "1",
        "revoked restart cannot open another provider connection"
    );
    super::assert_tree_absent(
        "protected T1 daemon sinks after restart denial",
        &provider_root.join("runne-daemon"),
        scanner,
    );
    super::t1_support::assert_profile_sqlite_absent(
        scanner,
        "AppCore profile after restart denial",
        desktop_db,
    );
    supervisor.stop().expect("graceful restarted shutdown");
}
