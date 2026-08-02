#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_bound_v2_bundled_process_renews_and_stops_without_v1_downgrade() {
    let temporary = tempfile::tempdir().expect("temporary V2 runtime root");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gocode-daemon"));
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
            .expect("protected launch spec")
            .with_provider_activation(ProviderActivationBindingV1::deterministic_v1());
    let mut process = DevelopmentBundledRuntimeLauncher::new()
        .launch(&spec)
        .expect("provider-bound V2 launch");
    assert_eq!(
        process.provider_activation(),
        Some(&ProviderActivationBindingV1::deterministic_v1())
    );

    let initial = process
        .take_runtime_profile()
        .expect("initial V2 profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("initial V2 session");
    assert!(process.matches_client(&initial));
    let initial_session = initial.session_info().clone();

    let renewed = process
        .renew_profile()
        .expect("V2 renewal")
        .connect(Duration::from_secs(10))
        .await
        .expect("renewed V2 session");
    assert!(process.matches_client(&renewed));
    assert_eq!(
        renewed.session_info().authority_id,
        initial_session.authority_id
    );
    assert_eq!(
        renewed.session_info().event_log_lineage_id,
        initial_session.event_log_lineage_id
    );
    assert_ne!(
        renewed.session_info().session_id,
        initial_session.session_id
    );

    process
        .request_graceful_stop()
        .expect("V2 authenticated shutdown");
    assert_eq!(
        process
            .wait_for_exit(Duration::from_secs(5))
            .expect("V2 daemon exit"),
        BundledRuntimeProcessStatus::Exited
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proven_owned_crash_recovers_the_exact_stable_hot_wal_binding() {
    let temporary = tempfile::tempdir().expect("temporary crash root");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gocode-daemon"));
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
            .expect("protected launch spec");

    let mut crashed = DevelopmentBundledRuntimeLauncher::new()
        .launch(&spec)
        .expect("initial protected runtime");
    assert_eq!(
        crashed.provider_activation(),
        None,
        "the no-provider compatibility path must remain V1 deterministic"
    );
    let initial_client = crashed
        .take_runtime_profile()
        .expect("initial protected profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("initial protected session");
    assert!(crashed.matches_client(&initial_client));
    let initial = initial_client.session_info().clone();
    drop(initial_client);

    crashed.terminate().expect("terminate exact owned child");
    assert_eq!(
        crashed
            .wait_for_exit(Duration::from_secs(5))
            .expect("reap exact owned child"),
        BundledRuntimeProcessStatus::Exited
    );
    let database = spec.runtime_root().join("gocode-daemon/event-log.db");
    assert!(
        database.with_extension("db-wal").exists() || database.with_extension("db-shm").exists(),
        "owned crash must exercise the hot-WAL recovery path"
    );
    drop(crashed);

    let mut recovered = DevelopmentBundledRuntimeLauncher::new()
        .launch(&spec)
        .expect("recover exact stable protected runtime");
    let recovered_client = recovered
        .take_runtime_profile()
        .expect("recovered protected profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("recovered protected session");
    assert!(recovered.matches_client(&recovered_client));
    let current = recovered_client.session_info();
    assert_eq!(current.authority_id, initial.authority_id);
    assert_eq!(current.event_log_lineage_id, initial.event_log_lineage_id);
    assert_eq!(current.launch_generation, initial.launch_generation + 1);
    assert_ne!(current.daemon_instance_id, initial.daemon_instance_id);
    assert_ne!(current.session_id, initial.session_id);

    recovered
        .request_graceful_stop()
        .expect("authenticated recovered shutdown");
    assert_eq!(
        recovered
            .wait_for_exit(Duration::from_secs(5))
            .expect("recovered exit"),
        BundledRuntimeProcessStatus::Exited
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_activation_recovers_across_crash_and_durable_write_fault_matrix() {
    let _process_guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gocode-daemon"));
    for fault in [
        FirstActivationFaultPoint::BeforePreparePersistence,
        FirstActivationFaultPoint::AfterPrepareFileSync,
        FirstActivationFaultPoint::AfterPreparePersistence,
        FirstActivationFaultPoint::BeforeCommit,
        FirstActivationFaultPoint::AfterCommit,
        FirstActivationFaultPoint::AfterEventLogCreation,
        FirstActivationFaultPoint::BeforeFinalPin,
        FirstActivationFaultPoint::AfterFinalPinFileSync,
        FirstActivationFaultPoint::AfterFinalPin,
    ] {
        let temporary = tempfile::tempdir().expect("temporary fault root");
        let spec =
            ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
                .expect("protected launch spec");
        let activation = spec.runtime_root().join(".desktop-protected-activation");
        let pending_path = activation.join("pending-first-activation-v1.json");
        let stable_path = activation.join("stable-binding-v1.json");

        let error = DevelopmentBundledRuntimeLauncher::new()
            .launch_for_test(&spec, random_secret(), false, Some(fault))
            .expect_err("injected activation fault must abort and reap the child");
        assert_eq!(
            error,
            ProtectedBundledRuntimeError::ActivationStateUnavailable
        );

        let prepared_stable = if pending_path.exists() {
            let pending: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&pending_path).expect("read durable pending activation"),
            )
            .expect("pending activation JSON");
            Some(pending["stable"].clone())
        } else {
            None
        };

        let mut recovered = DevelopmentBundledRuntimeLauncher::new()
            .launch(&spec)
            .unwrap_or_else(|error| panic!("exact recovery after {fault:?}: {error}"));
        let profile = recovered
            .take_runtime_profile()
            .expect("recovered one-time profile");
        let client = profile
            .connect(Duration::from_secs(10))
            .await
            .unwrap_or_else(|error| panic!("recovered session after {fault:?}: {error}"));
        assert!(recovered.matches_client(&client));
        let stable: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&stable_path).expect("final stable pin"))
                .expect("stable JSON");
        if let Some(prepared_stable) = prepared_stable {
            assert_eq!(
                stable, prepared_stable,
                "recovery after {fault:?} must preserve the exact preparation"
            );
        }
        assert!(
            !pending_path.exists(),
            "recovery after {fault:?} must finish the exact final pin"
        );
        assert!(
            spec.runtime_root()
                .join("gocode-daemon/event-log.db")
                .exists(),
            "recovery after {fault:?} must leave one usable Event Log"
        );
        recovered
            .request_graceful_stop()
            .expect("authenticated recovered shutdown");
        assert_eq!(
            recovered
                .wait_for_exit(Duration::from_secs(10))
                .expect("wait for recovered child"),
            gocode_platform_desktop::BundledRuntimeProcessStatus::Exited
        );
    }
}
