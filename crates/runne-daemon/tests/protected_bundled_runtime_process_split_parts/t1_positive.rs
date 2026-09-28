use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "launched with an explicit test-only fixture environment by the parent test"]
async fn t1_protected_provider_http_and_runtime_client_replay_child() {
    let _guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let session_bus_socket =
        super::t1_support::fixture_session_bus(temporary.path(), "session-bus.sock");
    let executable =
        owner_private::ControlledExecutable::copy_with_writer_from(env!("CARGO_BIN_EXE_runned"));
    let runtime_root = temporary.path().join("runtime");
    let spec = ProtectedBundledRuntimeLaunchSpec::new(executable.path(), &runtime_root)
        .expect("protected T1 launch spec")
        .with_openai_provider_activation()
        .with_validated_session_bus_address(&session_bus_socket)
        .expect("fixture session bus address");
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    supervisor.start().expect("protected T1 launch");
    let profile = supervisor
        .take_runtime_profile()
        .expect("one-time protected profile");
    let client = profile
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
    if !workspace.is_open() {
        let open_identity = runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("t1-open-{}", runne_runtime_client::CanonicalId::now_v7()),
        )
        .expect("open command identity");
        client
            .open_workspace(
                runne_runtime_client::ExistingWorkspaceRequest::new(
                    open_identity,
                    workspace_id,
                    workspace.version(),
                )
                .expect("open request"),
            )
            .await
            .expect("open bound workspace");
    }
    let confirmed = super::t1_trust_control::grant_through_public_control(
        &client,
        runtime_project_id,
        workspace_id,
    )
    .await;
    let old_root_version = confirmed
        .root_admission_version()
        .expect("first root admission version");
    super::t1_trust_control::assert_rebound_root_conflicts(
        &mut supervisor,
        &client,
        temporary.path(),
        runtime_project_id,
        workspace_id,
        workspace_api_id,
        old_root_version,
    )
    .await;
    let before = core
        .open_project_conversation(project)
        .await
        .expect("open trusted runtime conversation");
    let conversation_id =
        runne_runtime_client::CanonicalId::parse(&before.conversation_id).expect("conversation id");
    let scope = runne_runtime_client::ReplayScope::new(
        runne_runtime_client::ReplayAggregateKind::Conversation,
        conversation_id,
    );
    let mut live = client
        .catch_up(scope, None, |_| Ok::<_, ()>(()))
        .await
        .expect("authenticated replay catch-up");

    for denied_canary in &denied_canaries {
        let denied = core
            .send_project_message(project, denied_canary)
            .await
            .expect_err("registered frozen canary must be denied before provider effect");
        assert!(matches!(
            denied,
            runne_app_core::AppCoreError::ProhibitedInputRejected
        ));
        assert!(!format!("{denied:?}").contains(denied_canary));
        assert!(
            !runtime_root
                .join("fixture-provider-connection-count")
                .exists(),
            "denied provider input must not open the loopback transport"
        );
    }

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

    let mut saw_sse_response = false;
    for _ in 0..8 {
        let event = tokio::time::timeout(Duration::from_secs(5), live.next_event())
            .await
            .expect("replay SSE delivery timeout")
            .expect("replay SSE delivery");
        match event {
            runne_runtime_client::ReplayStreamEvent::Delivery(delivery) => {
                let fixture_response = match delivery.event().payload() {
                    runne_runtime_client::CanonicalReplayPayload::Conversation(
                        runne_runtime_client::ConversationReplayPayload::MessageAppended {
                            role,
                            text,
                            ..
                        },
                    ) => {
                        assert_absent("decoded replay SSE message", text.as_bytes(), &scanner);
                        *role == runne_runtime_client::ConversationMessageRole::Assistant
                            && text == "fixture response"
                    }
                    _ => false,
                };
                if fixture_response {
                    saw_sse_response = true;
                }
                live.acknowledge(&delivery)
                    .await
                    .expect("acknowledge validated SSE delivery");
                if saw_sse_response {
                    break;
                }
            }
            runne_runtime_client::ReplayStreamEvent::Heartbeat => {}
            runne_runtime_client::ReplayStreamEvent::Terminal(_) => break,
        }
    }
    assert!(
        saw_sse_response,
        "assistant output must arrive over replay SSE"
    );
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
    super::t1_support::assert_one_settled_dispatch(&daemon_db);
}
