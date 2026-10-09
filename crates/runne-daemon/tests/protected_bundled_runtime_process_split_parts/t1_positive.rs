use super::*;
#[path = "t1_positive/d2_pending.rs"]
mod d2_pending;
#[path = "t1_positive/managed_ask.rs"]
mod managed_ask;
#[path = "t1_positive/replay_sse.rs"]
mod replay_sse;
#[path = "t1_positive/trust.rs"]
mod trust;
#[path = "t1_positive/workspace.rs"]
mod workspace;
pub(super) use d2_pending::restart_same_root;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "launched with an explicit test-only fixture environment by the parent test"]
async fn t1_protected_provider_http_and_runtime_client_replay_child() {
    let _guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let session_bus_socket =
        super::t1_support::fixture_session_bus(temporary.path(), "session-bus.sock");
    let executable = super::t1_positive_canaries::copy_controlled_runtime();
    let runtime_root = temporary.path().join("runtime");
    let spec = ProtectedBundledRuntimeLaunchSpec::new(executable.path(), &runtime_root)
        .expect("protected T1 launch spec")
        .with_openai_provider_activation()
        .with_validated_session_bus_address(&session_bus_socket)
        .expect("fixture session bus address");
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    super::t1_startup_diagnostic::start(&mut supervisor, &runtime_root);
    let profile = supervisor
        .take_runtime_profile()
        .expect("one-time protected profile");
    let mut client = profile
        .connect(Duration::from_secs(10))
        .await
        .expect("authenticated protected runtime client");
    assert_eq!(
        client.transport_kind(),
        RuntimeTransportKind::ProtectedBundled
    );
    supervisor
        .record_client_ready(&client)
        .expect("exact protected readiness");
    let desktop_db = temporary.path().join("desktop-profile.sqlite3");
    let profile_key = [0x52; 32];
    let secure =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile_key));
    let core = AppCore::open_bundled_anchored(&desktop_db, secure.clone(), profile_key)
        .expect("test AppCore");
    let lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin AppCore runtime install");
    assert_eq!(
        core.install_bundled_runtime_client(lease, client.clone())
            .await
            .expect("install protected client"),
        RuntimeAvailability::Live
    );
    let project_directory = temporary.path().join("project");
    let denied_canaries = super::t1_support::frozen_registered_canaries();
    // The governed workspace path keeps the hostile project sources available
    // for the wire-sink assertion; NM-11's separate TextOnly lifecycle lives
    // in `t1_text_only` and does not use this workspace conversation.
    super::t1_support::seed_hostile_workspace(&project_directory);
    let project = core
        .open_local_project(&project_directory)
        .expect("open test project");
    let daemon_db = runtime_root.join("runne-daemon/event-log.db");
    let (runtime_project_id, workspace_id) =
        prepare_canonical_conversation_workspace_without_trust(&core, project).await;
    let workspace_api_id = runne_api::WorkspaceId::from_bytes(
        uuid::Uuid::parse_str(&workspace_id.to_string())
            .expect("workspace UUID")
            .into_bytes(),
    );
    let workspace = client
        .get_workspace(workspace_id)
        .await
        .expect("created workspace metadata");
    let root = runne_platform_desktop::VerifiedRootHandle::open(&project_directory)
        .expect("open synthetic project root handle");
    let admission = supervisor
        .prepare_root_admission(&root, workspace_api_id, workspace.version())
        .expect("prepare exact retained root admission");
    let admission = runne_runtime_client::ProtectedRootAdmission::from_verified(admission)
        .expect("wrap protected admission");
    let bind_identity = runne_runtime_client::CommandIdentity::new(
        runne_runtime_client::CanonicalId::now_v7(),
        format!("t1-bind-{}", runne_runtime_client::CanonicalId::now_v7()),
    )
    .expect("bind command identity");
    client
        .bind_workspace_root(
            runne_runtime_client::BindWorkspaceRootRequest::new(
                bind_identity,
                workspace_id,
                workspace.version(),
                &admission,
            )
            .expect("bind request"),
        )
        .await
        .expect("bind retained root");
    let workspace = client
        .get_workspace(workspace_id)
        .await
        .expect("bound workspace metadata");
    workspace::open_if_closed(
        &client,
        workspace_id,
        workspace.is_open(),
        workspace.version(),
    )
    .await;
    trust::confirm_rebound_project_trust(
        &mut supervisor,
        &client,
        temporary.path(),
        runtime_project_id,
        workspace_id,
        workspace_api_id,
    )
    .await;
    managed_ask::seed_after_trust(&daemon_db, runtime_project_id);
    let before = core
        .open_project_conversation(project)
        .await
        .expect("open trusted runtime conversation");
    let conversation_id =
        runne_runtime_client::CanonicalId::parse(&before.conversation_id).expect("id");
    if d2_pending::dispatch_if_requested(
        &mut client,
        conversation_id,
        workspace_id,
        temporary.path(),
        &daemon_db,
        &runtime_root,
        &mut supervisor,
        executable.path(),
        &session_bus_socket,
    )
    .await
    {
        return;
    }
    let scope = runne_runtime_client::ReplayScope::new(
        runne_runtime_client::ReplayAggregateKind::Conversation,
        conversation_id,
    );
    let mut live = client
        .catch_up(scope, None, |_| Ok::<_, ()>(()))
        .await
        .expect("authenticated replay catch-up");
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_ONLY").is_some()
        || std::env::var_os("RUNNE_TEST_T1_LOCAL_CRASH_ONLY").is_some()
    {
        drop(core);
        drop(live);
        let project_directory = temporary.path().join("rebound-project");
        let local_context = super::t1_taskrun_support::LocalTaskRunContext {
            client,
            conversation_id,
            workspace_id,
            project_directory: &project_directory,
            database: &daemon_db,
            session_bus_socket: &session_bus_socket,
            runtime_root: &runtime_root,
            executable: &executable,
            supervisor: &mut supervisor,
        };
        super::t1_local_only::exercise_if_requested(local_context).await;
        return;
    }
    super::t1_positive_canaries::assert_denied_before_provider(
        &core,
        project,
        &denied_canaries,
        &runtime_root,
    )
    .await;
    let completed = core
        .send_project_message(project, "fixture input")
        .await
        .expect("provider-backed generation");
    assert!(
        completed
            .messages
            .iter()
            .any(|message| { message.role == "assistant" && message.text == "fixture response" })
    );
    let mut forbidden = nm10_rules::secret_patterns();
    forbidden.extend(nm10_rules::project_patterns());
    forbidden.push("RUNNE_T1_FAKE");
    let materials = forbidden
        .into_iter()
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let scanner = secret_scan::SecretScanner::new(material_representations(&materials))
        .unwrap_or_else(|_| panic!("T1 frozen sink scanner"));
    for message in &completed.messages {
        assert_absent(
            "AppCore returned message",
            message.text.as_bytes(),
            &scanner,
        );
    }
    replay_sse::assert_fixture_response_over_sse(&mut live, &scanner).await;
    super::t1_taskrun_support::exercise_automatic_worker(
        &client,
        &mut live,
        conversation_id,
        workspace_id,
        &daemon_db,
    )
    .await;
    super::t1_local_commands::exercise_local_commands(
        &client,
        conversation_id,
        workspace_id,
        &temporary.path().join("rebound-project"),
        &daemon_db,
        &runtime_root,
    )
    .await;
    super::t1_local_cancel::exercise_running_cancel(
        &client,
        conversation_id,
        workspace_id,
        &temporary.path().join("rebound-project"),
        &daemon_db,
    )
    .await;
    let revoked_revision = super::t1_support::set_project_trust_status(
        &daemon_db,
        runne_application::project_trust::ProjectTrustStatus::Untrusted,
    );
    let terminal = tokio::time::timeout(Duration::from_secs(10), live.next_event())
        .await
        .expect("revoked live SSE terminal timeout")
        .expect("revocation is an in-band terminal event");
    assert!(matches!(
        terminal,
        runne_runtime_client::ReplayStreamEvent::Terminal(terminal)
            if terminal.code() == runne_runtime_client::ReplayTerminalCode::AuthorizationRevoked
    ));
    let provider_root = runtime_root.as_path();
    super::t1_trust_control::assert_persistence_sinks(provider_root, &desktop_db, &scanner);
    supervisor.stop().expect("graceful protected shutdown");
    drop(live);
    drop(client);
    drop(core);
    super::t1_restart::assert_revoked_restart(super::t1_restart::RevokedRestartContext {
        executable: &executable,
        runtime_root: &runtime_root,
        desktop_db: &desktop_db,
        profile_key,
        secure,
        project_directory: &project_directory,
        conversation_id,
        provider_root,
        daemon_database: &daemon_db,
        revoked_revision,
        scanner: &scanner,
    })
    .await;
    super::t1_taskrun_support::assert_three_settled_dispatches(&daemon_db);
}
