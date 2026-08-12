
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_bundled_process_rotates_session_restarts_and_stops_owned_child() {
    let _process_guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let executable = owner_private::ControlledExecutable::copy_from(env!("CARGO_BIN_EXE_gocode-daemon"));
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(executable.path(), &temporary.path().join("runtime"))
            .expect("protected launch spec");
    let runtime_root = spec.runtime_root().to_path_buf();
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);

    supervisor.start().expect("first protected launch");
    assert_eq!(
        supervisor.state(),
        BundledRuntimeLifecycleState::Handshaking
    );
    let initial_profile = supervisor
        .take_runtime_profile()
        .expect("initial one-time profile");
    let initial_client = initial_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("initial protected client");
    assert_eq!(
        initial_client.transport_kind(),
        RuntimeTransportKind::ProtectedBundled
    );
    supervisor
        .record_client_ready(&initial_client)
        .expect("exact initial readiness");
    let initial = initial_client.session_info().clone();

    supervisor
        .queue_renewal_profile()
        .expect("queue session renewal");
    let renewed_profile = supervisor
        .take_runtime_profile()
        .expect("renewed one-time profile");
    let renewed_client = renewed_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("renewed protected client");
    supervisor
        .record_client_ready(&renewed_client)
        .expect("exact renewed readiness");
    let renewed = renewed_client.session_info().clone();
    assert_eq!(renewed.authority_id, initial.authority_id);
    assert_eq!(renewed.event_log_lineage_id, initial.event_log_lineage_id);
    assert_eq!(renewed.daemon_instance_id, initial.daemon_instance_id);
    assert_eq!(renewed.launch_generation, initial.launch_generation);
    assert_ne!(renewed.session_id, initial.session_id);

    let desktop_database = temporary.path().join("desktop-profile.sqlite3");
    let project_directory = temporary.path().join("project");
    std::fs::create_dir(&project_directory).expect("project directory");
    let core = AppCore::open_with_runtime_mode(&desktop_database, RuntimeMode::Bundled)
        .expect("bundled AppCore");
    let initial_lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin protected AppCore activation");
    assert_eq!(
        core.install_bundled_runtime_client(initial_lease, renewed_client)
            .await
            .expect("install protected client"),
        RuntimeAvailability::Live
    );
    let project = core
        .open_local_project(&project_directory)
        .expect("open local project");
    core.open_project_conversation(project)
        .await
        .expect("open runtime conversation");
    let before_restart = core
        .send_project_message(project, "first protected message")
        .await
        .expect("send before restart");
    assert_eq!(before_restart.messages.len(), 2);
    let before_ids = before_restart
        .messages
        .iter()
        .map(|message| message.message_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        before_ids.iter().collect::<HashSet<_>>().len(),
        before_ids.len()
    );

    assert_eq!(
        supervisor.stop().expect("graceful owned stop"),
        BundledRuntimeStopDisposition::Graceful
    );
    assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    assert!(!supervisor.owns_runtime());

    let stable_record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            runtime_root
                .join(".desktop-protected-activation")
                .join("stable-binding-v1.json"),
        )
        .expect("stable activation record"),
    )
    .expect("stable record JSON");
    let authority = stable_record["authority_id"]
        .as_array()
        .expect("stable authority")
        .iter()
        .map(|value| u8::try_from(value.as_u64().expect("authority byte")).expect("u8 byte"))
        .collect::<Vec<_>>();
    assert_eq!(hex::encode(&authority), initial.authority_id);
    let sidecar = std::fs::read(
        runtime_root
            .join("gocode-daemon")
            .join("local-session-authority-id"),
    )
    .expect("authority sidecar");
    assert_eq!(sidecar, authority);
    let daemon_profile_directory = runtime_root.join("gocode-daemon");
    assert!(
        !daemon_profile_directory
            .join("client-profile.json")
            .exists()
    );
    assert!(
        std::fs::read_dir(&daemon_profile_directory)
            .expect("daemon profile directory")
            .all(|entry| {
                let name = entry
                    .expect("daemon profile entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned();
                !name.starts_with("bootstrap-") && !name.ends_with(".secret")
            })
    );

    let restart_lease = core
        .begin_bundled_runtime_restart()
        .await
        .expect("fence old AppCore session");
    supervisor.start().expect("fresh protected restart");
    let restarted_profile = supervisor
        .take_runtime_profile()
        .expect("restart one-time profile");
    let restarted_client = restarted_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("restarted protected client");
    supervisor
        .record_client_ready(&restarted_client)
        .expect("exact restarted readiness");
    let restarted = restarted_client.session_info().clone();
    assert_eq!(restarted.authority_id, initial.authority_id);
    assert_eq!(restarted.event_log_lineage_id, initial.event_log_lineage_id);
    assert_ne!(restarted.daemon_instance_id, initial.daemon_instance_id);
    assert_ne!(restarted.session_id, initial.session_id);
    assert_eq!(restarted.launch_generation, initial.launch_generation + 1);
    core.install_bundled_runtime_client(restart_lease, restarted_client)
        .await
        .expect("install restarted protected client");

    let resumed = core
        .open_project_conversation(project)
        .await
        .expect("resume conversation after restart");
    assert_eq!(
        resumed
            .messages
            .iter()
            .map(|message| message.message_id.as_str())
            .collect::<Vec<_>>(),
        before_ids.iter().map(String::as_str).collect::<Vec<_>>()
    );
    let after_restart = core
        .send_project_message(project, "second protected message")
        .await
        .expect("send after restart");
    assert_eq!(after_restart.messages.len(), 4);
    assert_eq!(
        after_restart
            .messages
            .iter()
            .map(|message| message.message_id.as_str())
            .collect::<HashSet<_>>()
            .len(),
        after_restart.messages.len()
    );

    let activation_directory = runtime_root.join(".desktop-protected-activation");
    for record in std::fs::read_dir(activation_directory).expect("activation records") {
        let path = record.expect("activation record").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(path).expect("record bytes");
        let text = String::from_utf8(bytes).expect("record JSON");
        assert!(!text.contains("secret"));
        assert!(!text.contains("bootstrap"));
        assert!(!text.contains("credential"));
        assert!(!text.contains("endpoint"));
    }

    assert_eq!(
        supervisor.stop().expect("second graceful owned stop"),
        BundledRuntimeStopDisposition::Graceful
    );
}
