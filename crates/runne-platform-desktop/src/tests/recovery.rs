    #[test]
    fn supervisor_keeps_shutdown_fence_after_graceful_wait_failure_and_retries() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, _) = FakeLauncher::new([Ok(FakeProcess::with_wait_failure_once([
            BundledRuntimeProcessStatus::Exited,
        ]))]);
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
            Err(BundledRuntimeSupervisorError::ProcessStatusUnavailable)
        );
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopping);
        supervisor
            .monitor()
            .expect("shutdown fence prevents restart");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);

        // A second independent supervisor proves that a pending shutdown can
        // retry the same owned launch after a transient wait failure.
        let clock = FakeClock::new(Instant::now());
        let (launcher, _) = FakeLauncher::new([Ok(FakeProcess::with_wait_failure_once([
            BundledRuntimeProcessStatus::Exited,
        ]))]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
        supervisor.start().expect("spawn owned process");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("prove current owned launch");
        let _ = supervisor.stop(
            &authenticated_handshake(),
            BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT,
        );
        assert_eq!(
            supervisor.stop(
                &authenticated_handshake(),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
            ),
            Ok(BundledRuntimeStopDisposition::Graceful)
        );
    }

    #[test]
    fn supervisor_keeps_shutdown_fence_when_retry_graceful_request_fails() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, _) =
            FakeLauncher::new([Ok(FakeProcess::with_wait_failure_then_graceful_failure([
                BundledRuntimeProcessStatus::Exited,
            ]))]);
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
            Err(BundledRuntimeSupervisorError::ProcessStatusUnavailable)
        );
        assert_eq!(
            supervisor.stop(
                &authenticated_handshake(),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
            ),
            Err(BundledRuntimeSupervisorError::GracefulStopUnavailable)
        );
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopping);
        supervisor
            .monitor()
            .expect("shutdown fence prevents restart after retry failure");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    }

    #[test]
    fn supervisor_retries_forced_termination_after_a_request_failure() {
        let clock = FakeClock::new(Instant::now());
        let (process, termination_requests) = FakeProcess::with_termination_failure_once([
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
            Err(BundledRuntimeSupervisorError::ForcedStopUnavailable)
        );
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopping);
        assert_eq!(
            supervisor.stop(
                &authenticated_handshake(),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
            ),
            Ok(BundledRuntimeStopDisposition::Forced)
        );
        assert_eq!(termination_requests.get(), 2);
    }

    #[test]
    fn supervisor_rejects_stale_ownership_without_stopping_the_current_launch() {
        let clock = FakeClock::new(Instant::now());
        let (process, graceful_stop_requests, termination_requests) =
            FakeProcess::with_stop_tracking([BundledRuntimeProcessStatus::Running]);
        let (launcher, _) = FakeLauncher::new([Ok(process)]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
        supervisor.start().expect("spawn owned process");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("prove current owned launch");
        let mut stale_identity = runtime_identity();
        stale_identity.session_id = "2".repeat(32);

        assert_eq!(
            supervisor.stop(
                &BundledRuntimeAuthenticatedHandshake::for_test(stale_identity),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT,
            ),
            Err(BundledRuntimeSupervisorError::ShutdownOwnershipMismatch)
        );
        assert_eq!(graceful_stop_requests.get(), 0);
        assert_eq!(termination_requests.get(), 0);
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Ready);
    }

    #[test]
    fn supervisor_restarts_after_an_unexpected_exit_and_backoff() {
        let start = Instant::now();
        let clock = FakeClock::new(start);
        let (launcher, spawn_count) =
            FakeLauncher::new([Ok(FakeProcess::exited()), Ok(FakeProcess::running())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock.clone(), launch_spec());

        supervisor.start().expect("initial spawn");
        supervisor.monitor().expect("observe unexpected exit");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Backoff);
        assert_eq!(spawn_count.get(), 1);

        prepare_next_profile_binding(&mut supervisor, &runtime_identity());
        clock.advance(Duration::from_secs(1));
        supervisor.monitor().expect("restart after backoff");
        assert_eq!(spawn_count.get(), 2);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::Handshaking
        );
    }

    #[test]
    fn supervisor_marks_a_failed_delayed_restart_as_failed_start() {
        let start = Instant::now();
        let clock = FakeClock::new(start);
        let (launcher, spawn_count) = FakeLauncher::new([Ok(FakeProcess::exited()), Err(())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock.clone(), launch_spec());

        supervisor.start().expect("initial spawn");
        supervisor.monitor().expect("observe unexpected exit");
        prepare_next_profile_binding(&mut supervisor, &runtime_identity());
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            supervisor.monitor(),
            Err(BundledRuntimeSupervisorError::SpawnFailed)
        );
        assert_eq!(spawn_count.get(), 2);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::FailedStart
        );
    }

    #[test]
    fn supervisor_exhausts_restart_budget_and_stable_readiness_resets_it() {
        let start = Instant::now();
        let clock = FakeClock::new(start);
        let (launcher, spawn_count) = FakeLauncher::new([
            Ok(FakeProcess::exited()),
            Ok(FakeProcess::exited()),
            Ok(FakeProcess::exited()),
            Ok(FakeProcess::exited()),
            Ok(FakeProcess::exited()),
            Ok(FakeProcess::exited()),
        ]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock.clone(), launch_spec());

        supervisor.start().expect("initial spawn");
        for delay in [1, 2, 5, 10, 30] {
            supervisor.monitor().expect("observe unexpected exit");
            assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Backoff);
            prepare_next_profile_binding(&mut supervisor, &runtime_identity());
            clock.advance(Duration::from_secs(delay));
            supervisor.monitor().expect("restart after backoff");
        }
        supervisor.monitor().expect("sixth unexpected exit");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Exhausted);
        assert_eq!(spawn_count.get(), 6);

        let (launcher, spawn_count) = FakeLauncher::new([Ok(FakeProcess::with_statuses([
            BundledRuntimeProcessStatus::Running,
            BundledRuntimeProcessStatus::Exited,
        ]))]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock.clone(), launch_spec());
        supervisor.start().expect("fresh supervisor spawn");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("matching authenticated handshake");
        clock.advance(UNEXPECTED_EXIT_WINDOW);
        supervisor.monitor().expect("reset stable readiness budget");
        supervisor.monitor().expect("observe post-reset exit");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Backoff);
        assert_eq!(spawn_count.get(), 1);
    }
