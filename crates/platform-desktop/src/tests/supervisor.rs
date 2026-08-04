    #[test]
    fn bundled_runtime_launch_spec_requires_an_absolute_direct_non_secret_launch() {
        assert_eq!(
            BundledRuntimeLaunchSpec::new(
                PathBuf::from("gocoded"),
                BundledRuntimeLaunchMode::Direct,
                None,
            ),
            Err(BundledRuntimeLaunchError::ExecutablePathNotAbsolute)
        );
        assert_eq!(
            BundledRuntimeLaunchSpec::new(
                absolute_test_executable(),
                BundledRuntimeLaunchMode::Shell,
                None,
            ),
            Err(BundledRuntimeLaunchError::ShellForbidden)
        );

        let spec = BundledRuntimeLaunchSpec::new(
            absolute_test_executable(),
            BundledRuntimeLaunchMode::Direct,
            None,
        )
        .expect("accept direct launch without a secret transport");
        assert_eq!(spec.executable(), absolute_test_executable());
    }

    #[test]
    fn bundled_runtime_launch_spec_fails_closed_for_every_secret_transport() {
        for transport in [
            BundledRuntimeSecretTransport::Environment,
            BundledRuntimeSecretTransport::Arguments,
            BundledRuntimeSecretTransport::File,
            BundledRuntimeSecretTransport::Stdout,
            BundledRuntimeSecretTransport::InheritedPipeOrHandle,
        ] {
            assert_eq!(
                BundledRuntimeLaunchSpec::new(
                    absolute_test_executable(),
                    BundledRuntimeLaunchMode::Direct,
                    Some(transport),
                ),
                Err(BundledRuntimeLaunchError::SecretTransportUnsupported)
            );
        }
    }

    #[test]
    fn supervisor_spawns_then_waits_for_authenticated_readiness() {
        let start = Instant::now();
        let clock = FakeClock::new(start);
        let (launcher, spawn_count) = FakeLauncher::new([Ok(FakeProcess::running())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());

        supervisor.start().expect("spawn succeeds");
        assert_eq!(spawn_count.get(), 1);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::Handshaking
        );

        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("matching authenticated handshake");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Ready);
    }

    #[test]
    fn supervisor_fails_closed_when_spawn_fails() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, spawn_count) = FakeLauncher::new([Err(()), Ok(FakeProcess::running())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());

        assert_eq!(
            supervisor.start(),
            Err(BundledRuntimeSupervisorError::SpawnFailed)
        );
        assert_eq!(spawn_count.get(), 1);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::FailedStart
        );

        prepare_next_profile_binding(&mut supervisor, &runtime_identity());
        supervisor
            .start()
            .expect("explicit retry after failed start");
        assert_eq!(spawn_count.get(), 2);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::Handshaking
        );
    }

    #[test]
    fn supervisor_fails_closed_without_a_secure_replay_profile_binding() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, spawn_count) = FakeLauncher::new([Ok(FakeProcess::running())]);
        let unbound_spec = BundledRuntimeLaunchSpec::new(
            absolute_test_executable(),
            BundledRuntimeLaunchMode::Direct,
            None,
        )
        .expect("valid unbound launch spec");
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, unbound_spec);

        assert_eq!(
            supervisor.start(),
            Err(BundledRuntimeSupervisorError::ProfileBindingUnavailable)
        );
        assert_eq!(spawn_count.get(), 0);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::FailedStart
        );
    }

    #[test]
    fn supervisor_rejects_repeated_start_without_replacing_the_owned_launch() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, spawn_count) =
            FakeLauncher::new([Ok(FakeProcess::running()), Ok(FakeProcess::running())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());

        supervisor.start().expect("initial spawn");
        let original_binding = supervisor
            .profile_binding
            .clone()
            .expect("owned profile binding");
        assert_eq!(
            supervisor.start(),
            Err(BundledRuntimeSupervisorError::AlreadyRunning)
        );
        assert_eq!(spawn_count.get(), 1);
        assert!(
            supervisor
                .profile_binding
                .as_ref()
                .is_some_and(|binding| binding == &original_binding)
        );
    }

    #[test]
    fn supervisor_rejects_a_stale_authenticated_handshake() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, _) =
            FakeLauncher::new([Ok(FakeProcess::exited()), Ok(FakeProcess::running())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock.clone(), launch_spec());
        supervisor.start().expect("first spawn");
        let mut stale_identity = runtime_identity();
        stale_identity.daemon_instance_id = "0199d55d-1a23-7000-8000-000000000003".to_owned();
        stale_identity.session_id = "2".repeat(32);
        let stale_handshake = BundledRuntimeAuthenticatedHandshake::for_test(stale_identity);
        supervisor.monitor().expect("observe first exit");
        let mut restarted_identity = runtime_identity();
        restarted_identity.daemon_instance_id = "0199d55d-1a23-7000-8000-000000000004".to_owned();
        prepare_next_profile_binding(&mut supervisor, &restarted_identity);
        clock.advance(Duration::from_secs(1));
        supervisor.monitor().expect("restart owned process");

        assert_eq!(
            supervisor.record_authenticated_ready(&stale_handshake),
            Err(BundledRuntimeSupervisorError::HandshakeMismatch)
        );
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::Handshaking
        );
    }

    #[test]
    fn supervisor_gracefully_stops_only_the_current_owned_launch() {
        let clock = FakeClock::new(Instant::now());
        let (process, graceful_stop_requests, termination_requests) =
            FakeProcess::with_stop_tracking([BundledRuntimeProcessStatus::Exited]);
        let (launcher, _) = FakeLauncher::new([Ok(process)]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
        supervisor.start().expect("spawn owned process");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("prove current owned launch");

        assert_eq!(
            supervisor.stop(
                &authenticated_handshake(),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
            ),
            Ok(BundledRuntimeStopDisposition::Graceful)
        );
        assert_eq!(graceful_stop_requests.get(), 1);
        assert_eq!(termination_requests.get(), 0);
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    }

    #[test]
    fn supervisor_forces_only_the_owned_process_after_graceful_timeout() {
        let clock = FakeClock::new(Instant::now());
        let (process, graceful_stop_requests, termination_requests) =
            FakeProcess::with_stop_tracking([
                BundledRuntimeProcessStatus::Running,
                BundledRuntimeProcessStatus::Exited,
            ]);
        let (launcher, _) = FakeLauncher::new([Ok(process)]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
        supervisor.start().expect("spawn owned process");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("prove current owned launch");

        assert_eq!(
            supervisor.stop(
                &authenticated_handshake(),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
            ),
            Ok(BundledRuntimeStopDisposition::Forced)
        );
        assert_eq!(graceful_stop_requests.get(), 1);
        assert_eq!(termination_requests.get(), 1);
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    }

    #[test]
    fn supervisor_retains_owned_process_when_forced_stop_is_unconfirmed() {
        let clock = FakeClock::new(Instant::now());
        let (process, graceful_stop_requests, termination_requests) =
            FakeProcess::with_stop_tracking([
                BundledRuntimeProcessStatus::Running,
                BundledRuntimeProcessStatus::Running,
                BundledRuntimeProcessStatus::Exited,
            ]);
        let (launcher, _) = FakeLauncher::new([Ok(process)]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
        supervisor.start().expect("spawn owned process");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("prove current owned launch");

        assert_eq!(
            supervisor.stop(
                &authenticated_handshake(),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
            ),
            Err(BundledRuntimeSupervisorError::ForcedStopUnconfirmed)
        );
        assert_eq!(graceful_stop_requests.get(), 1);
        assert_eq!(termination_requests.get(), 1);
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopping);

        supervisor.monitor().expect("retain supervision until exit");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    }

    #[test]
    fn supervisor_restores_ready_when_graceful_stop_request_fails() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, _) = FakeLauncher::new([Ok(FakeProcess::with_stop_failures(true, false))]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
        supervisor.start().expect("spawn owned process");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("prove current owned launch");

        assert_eq!(
            supervisor.stop(
                &authenticated_handshake(),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
            ),
            Err(BundledRuntimeSupervisorError::GracefulStopUnavailable)
        );
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Ready);
    }
