#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_process_resume_reapplies_unacknowledged_duplicate_once() {
    let _process_guard = process_e2e_guard().await;
    let directory = tempfile::tempdir().expect("owner-only temporary directory");
    set_owner_only(directory.path());
    let runtime_root = directory.path().join("runtime");
    let daemon_directory = runtime_root.join("runne-daemon");
    std::fs::create_dir_all(&daemon_directory).expect("create daemon directory");
    set_owner_only(&runtime_root);
    set_owner_only(&daemon_directory);
    let daemon_database = daemon_directory.join("event-log.db");
    let replay_key_path = daemon_directory.join("replay-integrity.key");
    let profile_path = daemon_directory.join("client-profile.json");
    let first_stop = directory.path().join("first.stop");

    let first_daemon = ChildDaemon::start(
        &daemon_database,
        &replay_key_path,
        &first_stop,
        "127.0.0.1:0",
        &profile_path,
        1,
    );
    let first_profile = profile_value(&profile_path);
    assert_eq!(first_profile["schemaVersion"], 3);
    assert_eq!(
        first_profile["transportProfileId"],
        "gocode-local-runtime/2"
    );
    let first_endpoint = endpoint_address(&first_profile);
    let stale_profile_path = directory.path().join("stale-client-profile.json");
    std::fs::copy(&profile_path, &stale_profile_path).expect("preserve stale profile");
    let first_identity = connect_identity(&profile_path).await;

    let desktop_database = directory.path().join("desktop.sqlite3");
    let security_profile = [0xD2; 32];
    let secure: Arc<dyn SecureStore> = Arc::new(
        runne_secure_store::test_support::DeterministicSecureStore::new(security_profile),
    );
    let project_path = directory.path().join("project");
    std::fs::create_dir(&project_path).expect("create project");
    let first_core = runne_app_core::test_support::open_anchored_external_local_core(
        &desktop_database,
        profile_path.clone(),
        Arc::clone(&secure),
        security_profile,
    )
    .expect("open first anchored desktop core");
    let project = first_core
        .open_local_project(&project_path)
        .expect("open local project");
    assert_eq!(
        first_core.connect_runtime().await.expect("connect runtime"),
        RuntimeAvailability::Live
    );
    let runtime_project_id = CanonicalId::now_v7();
    first_core
        .create_runtime_project(runtime_project_id, "Replay fixture".to_owned())
        .await
        .expect("create canonical project");
    // NM-06 context-scope contract: register the workspace BEFORE the
    // conversation exists and grant the project before the first delivery.
    prepare_project_conversation_anchor(
        &first_core,
        &desktop_database,
        project,
        runtime_project_id,
        &daemon_database,
        "Replay fixture",
    )
    .await;
    let opened = first_core
        .open_project_conversation(project)
        .await
        .expect("create conversation");
    assert_eq!(opened.stream_version, 1);
    assert!(opened.messages.is_empty());

    install_ack_failure_after_inclusive_duplicate(&daemon_database);
    let error = first_core
        .send_project_message(project, "hello")
        .await
        .expect_err("server acknowledgement is forced to fail");
    assert_eq!(error.to_string(), "runtime is unavailable");
    assert_eq!(
        first_core.bootstrap().expect("closed bootstrap").runtime,
        RuntimeAvailability::Reconnecting
    );
    let interrupted = local_projection_state(&desktop_database);
    assert_eq!(interrupted.event_sequence, 2);
    let interrupted_payload: serde_json::Value =
        serde_json::from_slice(&interrupted.payload).expect("interrupted projection JSON");
    assert_eq!(
        interrupted_payload["messages"]
            .as_array()
            .expect("interrupted messages")
            .len(),
        1
    );
    assert_eq!(
        interrupted_payload["messages"][0]["role"],
        serde_json::json!("user")
    );
    assert!(
        daemon_has_unacknowledged_delivery(&daemon_database, first_identity.generation),
        "the child daemon must retain a delivery beyond its acknowledged position: {:?}",
        daemon_replay_rows(&daemon_database)
    );
    drop(first_core);
    first_daemon.stop();
    remove_ack_failure(&daemon_database);

    let counterfeit = tokio::net::TcpListener::bind(first_endpoint)
        .await
        .expect("bind counterfeit listener");
    let counterfeit_task = tokio::spawn(async move {
        if let Ok((stream, _)) = counterfeit.accept().await {
            drop(stream);
        }
    });
    let counterfeit_core = runne_app_core::test_support::open_anchored_external_local_core(
        &desktop_database,
        stale_profile_path.clone(),
        Arc::clone(&secure),
        security_profile,
    )
    .expect("open counterfeit anchored client");
    assert!(counterfeit_core.connect_runtime().await.is_err());
    assert_eq!(
        counterfeit_core
            .bootstrap()
            .expect("counterfeit bootstrap")
            .runtime,
        RuntimeAvailability::Reconnecting
    );
    assert_eq!(
        local_projection_state(&desktop_database),
        interrupted,
        "counterfeit transport must not mutate the prior projection or cursor"
    );
    counterfeit_task.await.expect("counterfeit listener task");
    drop(counterfeit_core);

    let second_stop = directory.path().join("second.stop");
    let second_daemon = ChildDaemon::start(
        &daemon_database,
        &replay_key_path,
        &second_stop,
        &first_endpoint.to_string(),
        &profile_path,
        first_identity.generation + 1,
    );
    assert!(matches!(
        LocalRuntimeProfile::load(&stale_profile_path)
            .expect("stale profile shape")
            .connect(Duration::from_secs(5))
            .await,
        Err(LocalRuntimeConnectError::Transport(
            RuntimeTransportError::PeerIdentityMismatch
        ))
    ));
    let stale_core = runne_app_core::test_support::open_anchored_external_local_core(
        &desktop_database,
        stale_profile_path,
        Arc::clone(&secure),
        security_profile,
    )
    .expect("open stale anchored desktop core");
    assert!(stale_core.connect_runtime().await.is_err());
    assert_eq!(
        stale_core.bootstrap().expect("stale bootstrap").runtime,
        RuntimeAvailability::Reconnecting
    );
    assert_eq!(
        local_projection_state(&desktop_database),
        interrupted,
        "stale peer identity must not mutate the prior projection or cursor"
    );
    drop(stale_core);

    let second_identity = connect_identity(&profile_path).await;
    assert_eq!(second_identity.authority, first_identity.authority);
    assert_eq!(second_identity.principal, first_identity.principal);
    assert_eq!(second_identity.lineage, first_identity.lineage);
    assert_ne!(second_identity.instance, first_identity.instance);
    assert!(second_identity.generation > first_identity.generation);
    assert_ne!(second_identity.session, first_identity.session);

    let reopened = runne_app_core::test_support::open_anchored_external_local_core(
        &desktop_database,
        profile_path,
        secure,
        security_profile,
    )
    .expect("reopen anchored desktop core");
    assert_eq!(
        reopened.connect_runtime().await.expect("reconnect runtime"),
        RuntimeAvailability::Live
    );
    let restored = reopened
        .open_project_conversation(project)
        .await
        .expect("resume conversation");
    assert_eq!(restored.stream_version, 3);
    assert_eq!(restored.messages.len(), 2);
    assert_eq!(
        restored
            .messages
            .iter()
            .filter(|message| message.role == "user" && message.text == "hello")
            .count(),
        1
    );
    assert_eq!(
        restored
            .messages
            .iter()
            .filter(|message| {
                message.role == "assistant" && message.text == "Runne local response: hello"
            })
            .count(),
        1
    );
    let message_ids = restored
        .messages
        .iter()
        .map(|message| message.message_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(message_ids.len(), restored.messages.len());
    let completed = local_projection_state(&desktop_database);
    assert_eq!(completed.event_sequence, 3);
    assert!(completed.projection_revision > interrupted.projection_revision);
    assert!(completed.generation > interrupted.generation);
    wait_for_daemon_latest_cursor_acknowledged_and_closed(
        &daemon_database,
        second_identity.generation,
    );
    drop(reopened);
    second_daemon.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_process_wrong_authority_db_closes_fatal_without_local_mutation() {
    let _process_guard = process_e2e_guard().await;
    let fixture = ProcessFaultFixture::open().await;
    let before = local_projection_state(&fixture.desktop_database);
    replace_bound_runtime_authority(&fixture.desktop_database);

    let error = fixture
        .core()
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("wrong authority binding must fail closed");

    assert_eq!(error.to_string(), "runtime_identity_conflict");
    assert_eq!(
        fixture.core().bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Fatal
    );
    assert_eq!(local_projection_state(&fixture.desktop_database), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_process_retention_gap_closes_fail_closed_without_local_mutation() {
    let _process_guard = process_e2e_guard().await;
    let mut fixture = ProcessFaultFixture::open().await;
    let before = local_projection_state(&fixture.desktop_database);
    fixture.generate_text(1, "retained-after-gap").await;
    fixture.stop_daemon();
    delete_first_daemon_event(&fixture.daemon_database);
    fixture.restart_daemon();
    let core = fixture.reopen_core().await;

    let error = core
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("retention gap must fail closed");
    #[cfg(feature = "desktop-protected")]
    {
        // T1 NM-06: in the protected composition the delivery gate denies
        // a workspace retention gap before any recovery contract runs, so
        // the closed classification is the authorization revocation.
        assert_eq!(error.to_string(), "runtime_revoked");
        assert_eq!(
            core.bootstrap().expect("bootstrap").runtime,
            RuntimeAvailability::Revoked
        );
    }
    #[cfg(not(feature = "desktop-protected"))]
    {
        // Non-protected builds keep the legacy recovery classification:
        // the delivery trust gate does not exist there.
        assert_eq!(error.to_string(), "runtime_identity_conflict");
        assert_eq!(
            core.bootstrap().expect("bootstrap").runtime,
            RuntimeAvailability::Fatal
        );
    }
    assert_eq!(local_projection_state(&fixture.desktop_database), before);
}
