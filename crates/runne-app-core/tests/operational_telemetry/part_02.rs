#[test]
fn concurrent_records_have_strict_serialized_sequences() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = Arc::new(AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    ).expect("open core"));
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for generation in [1, 2] {
        let core = Arc::clone(&core);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            core.record_host_lifecycle(RuntimeLifecycleStatus::Degraded, None, Some(generation), generation)
        }));
    }
    barrier.wait();
    for thread in threads { thread.join().expect("thread join").expect("record transition"); }
    let snapshot = core.operational_telemetry_snapshot(3).expect("telemetry snapshot");
    let events = snapshot.host_lifecycle().events().expect("events");
    assert_eq!(events.iter().map(HostLifecycleEventV1::sequence).collect::<Vec<_>>(), [1, 2]);
}

#[test]
fn concurrent_channel_order_matches_allocated_sequences() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = Arc::new(
        AppCore::open_with_runtime_mode(
            &directory.path().join("profile.sqlite3"),
            RuntimeMode::Bundled,
        )
        .expect("open core"),
    );
    for round in 0..16_u64 {
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for generation in [round * 2 + 1, round * 2 + 2] {
            let core = Arc::clone(&core);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                core.record_host_lifecycle(
                    RuntimeLifecycleStatus::Degraded,
                    None,
                    Some(generation),
                    generation,
                )
            }));
        }
        barrier.wait();
        for thread in threads {
            thread
                .join()
                .expect("thread join")
                .expect("record transition");
        }
    }

    let snapshot = core
        .operational_telemetry_snapshot(33)
        .expect("telemetry snapshot");
    let sequences = snapshot
        .host_lifecycle()
        .events()
        .expect("events")
        .iter()
        .map(HostLifecycleEventV1::sequence)
        .collect::<Vec<_>>();
    assert_eq!(sequences, (1..=32).collect::<Vec<_>>());
}

#[test]
fn runtime_section_is_unavailable_without_a_validated_client_snapshot() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open(&directory.path().join("profile.sqlite3")).expect("open core");
    let snapshot = core.operational_telemetry_snapshot(10).expect("telemetry snapshot");
    assert!(snapshot.runtime().snapshot().is_none());
    assert!(snapshot.runtime().meta().freshness() == runne_runtime_client::TelemetryFreshnessV1::Unavailable);
}

#[test]
fn runtime_section_uses_the_validated_runtime_client_snapshot() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
    let origin = format!("http://{}", listener.local_addr().expect("listener address"));
    let wire = include_bytes!("../../../../contracts/gocode-ui-client-2/golden/operational-telemetry.json");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).expect("read request");
        write!(stream, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\n\r\n", wire.len()).expect("write headers");
        stream.write_all(wire).expect("write body");
    });
    let client = mock_authenticated_runtime_client(&origin, RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".to_owned(), schema_hash: "test".to_owned(),
        runtime_version: "test".to_owned(), capabilities: REQUIRED_RUNTIME_CAPABILITIES.iter().map(ToString::to_string).collect(),
        authority_id: "authority".to_owned(), principal_id: "principal".to_owned(),
        event_log_lineage_id: "lineage".to_owned(), daemon_instance_id: "daemon".to_owned(),
        launch_generation: 1, session_id: "session".to_owned(), authorization_epoch: 1,
        sensitivity_ceiling: "sensitive".to_owned(), certificate_sha256: "11".repeat(32), capability_digest: "22".repeat(32),
    }).expect("mock client");
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), client).expect("open core");
    let snapshot = core.operational_telemetry_snapshot(10).expect("telemetry snapshot");
    assert_eq!(snapshot.runtime().snapshot().expect("runtime snapshot").launch_generation(), 1);
    server.join().expect("server join");
}

#[test]
fn automatic_bundled_restart_records_one_restart_episode() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(&directory.path().join("profile.sqlite3"), RuntimeMode::Bundled).expect("open core");
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime")
        .block_on(core.begin_bundled_runtime_restart()).expect("begin restart");
    let snapshot = core.operational_telemetry_snapshot(10).expect("telemetry snapshot");
    let current = snapshot.host_lifecycle().current().expect("current lifecycle");
    assert_eq!(current.lifecycle(), RuntimeLifecycleStatus::Restarting);
    assert_eq!(current.restart_ordinal(), Some(1));
    assert_eq!(current.runtime_launch_generation(), Some(1));
}

#[test]
fn bundled_shutdown_does_not_allocate_a_restart_ordinal() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(&directory.path().join("profile.sqlite3"), RuntimeMode::Bundled).expect("open core");
    core.record_host_lifecycle(RuntimeLifecycleStatus::Ready, None, Some(1), 1).expect("ready lifecycle");
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime")
        .block_on(core.fence_bundled_runtime_shutdown()).expect("shutdown fence");
    let snapshot = core.operational_telemetry_snapshot(10).expect("telemetry snapshot");
    let current = snapshot.host_lifecycle().current().expect("current lifecycle");
    assert_eq!(current.lifecycle(), RuntimeLifecycleStatus::Restarting);
    assert_eq!(current.restart_ordinal(), Some(0));
}

#[test]
fn all_closed_lifecycle_failure_combinations_follow_the_contract() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open_with_runtime_mode(&directory.path().join("profile.sqlite3"), RuntimeMode::Bundled).expect("open core");
    for (index, lifecycle) in [RuntimeLifecycleStatus::Starting, RuntimeLifecycleStatus::Ready, RuntimeLifecycleStatus::Restarting].into_iter().enumerate() {
        assert!(core.record_host_lifecycle(lifecycle, Some(RuntimeFailureCode::ProtectedActivationUnavailable), Some((index + 1) as u64), 1).is_err());
    }
    for (index, failure) in RuntimeFailureCode::ALL.into_iter().enumerate() {
        core.record_host_lifecycle(RuntimeLifecycleStatus::Failed, Some(failure), Some((index + 10) as u64), 1)
            .expect("failed lifecycle allows every closed failure code");
    }
    core.record_host_lifecycle(RuntimeLifecycleStatus::Degraded, None, Some(20), 1).expect("degraded lifecycle allows no failure");
}

#[test]
fn telemetry_types_do_not_expose_debug_or_unbounded_payload_markers() {
    let source = include_str!("../../src/lib_parts/operational_telemetry.rs");
    for forbidden in ["Debug", "String", "HashMap", "BTreeMap", "Path"] {
        assert!(!source.contains(forbidden), "forbidden marker: {forbidden}");
    }
}
