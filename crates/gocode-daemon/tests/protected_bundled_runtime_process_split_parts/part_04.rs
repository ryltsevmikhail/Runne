
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_protected_material_is_absent_from_every_forbidden_local_sink() {
    let temporary = tempfile::tempdir().expect("temporary audit root");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gocode-daemon"));
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
            .expect("protected launch spec");
    let runtime_root = spec.runtime_root().to_path_buf();
    let launch_secret = random_secret();
    let mut process = DevelopmentBundledRuntimeLauncher::new()
        .launch_for_test(&spec, launch_secret, true, None)
        .expect("audited protected launch");

    let initial_profile = process
        .take_runtime_profile()
        .expect("initial audited profile");
    let initial_bootstrap = initial_profile.test_bootstrap_material();
    let activation_keys = process.test_activation_key_material().into_values();
    let initial_client = initial_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("initial audited client");
    let initial_session_authority = initial_client.test_session_authority();
    assert!(process.matches_client(&initial_client));

    let renewed_profile = process.renew_profile().expect("audited renewal ticket");
    let renewal_bootstrap_ticket = renewed_profile.test_bootstrap_material();
    let renewed_client = renewed_profile
        .connect(Duration::from_secs(10))
        .await
        .expect("renewed audited client");
    let renewed_session_authority = renewed_client.test_session_authority();
    assert!(process.matches_client(&renewed_client));

    let mut materials = vec![
        launch_secret.to_vec(),
        initial_bootstrap.as_ref().to_vec(),
        renewal_bootstrap_ticket.as_ref().to_vec(),
        initial_session_authority.as_ref().to_vec(),
        renewed_session_authority.as_ref().to_vec(),
    ];
    materials.extend(
        activation_keys
            .into_iter()
            .filter(|key| key.as_ref() != [0; 32])
            .map(|key| key.as_ref().to_vec()),
    );
    assert!(
        materials.iter().all(|material| material != &[0; 32]),
        "every audited category must be non-zero"
    );
    assert_eq!(
        materials.iter().collect::<HashSet<_>>().len(),
        materials.len(),
        "raw secret, derived keys, renewal ticket and session authorities must be distinct"
    );
    let representations = material_representations(&materials);

    let desktop_database = temporary.path().join("desktop-audit.sqlite3");
    let project_directory = temporary.path().join("audit-project");
    std::fs::create_dir(&project_directory).expect("audit project directory");
    let core = AppCore::open_with_runtime_mode(&desktop_database, RuntimeMode::Bundled)
        .expect("audit AppCore");
    let lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin audited AppCore activation");
    core.install_bundled_runtime_client(lease, renewed_client)
        .await
        .expect("install audited protected client");
    let project = core
        .open_local_project(&project_directory)
        .expect("open audit project");
    core.open_project_conversation(project.id)
        .await
        .expect("open audited conversation");
    let timeline = core
        .send_project_message(project.id, "safe protected audit message")
        .await
        .expect("send audited message");
    let renderer_frames = [
        serde_json::to_vec(&core.bootstrap().expect("renderer bootstrap")).unwrap(),
        serde_json::to_vec(&timeline).unwrap(),
        serde_json::to_vec(
            &core
                .diagnostics("test-version", "test-platform")
                .expect("renderer diagnostics"),
        )
        .unwrap(),
    ]
    .concat();
    assert_absent("renderer frames", &renderer_frames, &representations);

    let safe_error_frames = format!(
        "{process:?};{};{}",
        ProtectedBundledRuntimeError::ActivationStateUnavailable,
        ProtectedBundledRuntimeError::LaunchAuthority(
            gocode_api::LaunchAuthorityError::ReadinessProofMismatch
        )
    );
    assert_absent(
        "renderer-safe errors",
        safe_error_frames.as_bytes(),
        &representations,
    );

    assert_tree_absent(temporary.path(), &representations);

    let mut broker = SecretBroker::new();
    for (index, material) in materials.iter().enumerate() {
        broker
            .register(&format!("protected-audit-{index}"), material.clone())
            .expect("register audited protected material");
    }
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(broker.prohibited_content_guard());
    for material in &materials {
        for boundary in [
            CanonicalContentBoundary::CanonicalMutation,
            CanonicalContentBoundary::OutboundDelivery,
        ] {
            assert!(matches!(
                guard.inspect(boundary, material),
                Ok(ContentDisposition::Prohibited { .. })
            ));
        }
    }

    let exporter = VerificationExporter::new(Arc::clone(&guard));
    let safe_export = exporter
        .export_run_json(
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            "completed",
            Some("passed"),
            0,
        )
        .expect("safe export");
    assert_absent("export", &safe_export, &representations);
    for material in &materials {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(material);
        assert!(
            exporter
                .export_run_json(
                    uuid::Uuid::now_v7(),
                    uuid::Uuid::now_v7(),
                    &encoded,
                    None,
                    0,
                )
                .is_err(),
            "protected material must be denied before export"
        );
    }

    let backup = InMemoryBackupStore::new(Arc::clone(&guard));
    let manifest = backup
        .create_backup(
            vec![StreamInventory {
                stream_name: "safe-stream".into(),
                event_count: 1,
                first_sequence: 1,
                last_sequence: 1,
            }],
            VerificationDigest::from_bytes([1; 32]),
        )
        .expect("safe synthetic backup");
    assert_absent(
        "backup",
        &backup
            .archive_bytes(&manifest.backup_id)
            .expect("backup bytes"),
        &representations,
    );
    let safe_archive_count = backup.archive_count();
    for material in &materials {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(material);
        assert!(
            backup
                .create_backup(
                    vec![StreamInventory {
                        stream_name: encoded,
                        event_count: 1,
                        first_sequence: 1,
                        last_sequence: 1,
                    }],
                    VerificationDigest::from_bytes([1; 32]),
                )
                .is_err(),
            "protected material must be denied before backup"
        );
        assert_eq!(backup.archive_count(), safe_archive_count);
    }

    process
        .request_graceful_stop()
        .expect("authenticated audited shutdown");
    assert_eq!(
        process
            .wait_for_exit(Duration::from_secs(10))
            .expect("wait for audited child"),
        gocode_platform_desktop::BundledRuntimeProcessStatus::Exited
    );
    let (stdout, stderr) = process
        .take_captured_output_for_test()
        .expect("captured audited output");
    assert_absent("captured stdout", &stdout, &representations);
    assert_absent("captured stderr/logs", &stderr, &representations);
    drop(core);

    assert_tree_absent(&runtime_root, &representations);
    assert_tree_absent(temporary.path(), &representations);
    assert_tracked_fixtures_absent(&representations);
}
