    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    use super::{
        BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT, BundledRuntimeAuthenticatedHandshake,
        BundledRuntimeAuthenticatedIdentity, BundledRuntimeBackoff, BundledRuntimeClock,
        BundledRuntimeLaunchError, BundledRuntimeLaunchMode, BundledRuntimeLaunchSpec,
        BundledRuntimeLifecycleState, BundledRuntimeProcess, BundledRuntimeProcessLauncher,
        BundledRuntimeProcessStatus, BundledRuntimeProfileBinding,
        BundledRuntimeRestartDisposition, BundledRuntimeSecretTransport,
        BundledRuntimeStopDisposition, BundledRuntimeSupervisor, BundledRuntimeSupervisorError,
        DisplayWorkArea, ProfileLock, UNEXPECTED_EXIT_WINDOW, WindowGeometry,
        restore_window_geometry,
    };
    #[derive(Clone)]
    struct FakeClock(Rc<Cell<Instant>>);

    impl FakeClock {
        fn new(now: Instant) -> Self {
            Self(Rc::new(Cell::new(now)))
        }

        fn advance(&self, duration: Duration) {
            self.0.set(self.0.get() + duration);
        }
    }

    impl BundledRuntimeClock for FakeClock {
        fn now(&self) -> Instant {
            self.0.get()
        }
    }

    struct FakeProcess {
        statuses: VecDeque<BundledRuntimeProcessStatus>,
        graceful_stop_requests: Rc<Cell<u32>>,
        termination_requests: Rc<Cell<u32>>,
        graceful_stop_outcomes: VecDeque<bool>,
        wait_failures_remaining: usize,
        terminate_failures_remaining: usize,
    }

    impl FakeProcess {
        fn with_statuses(statuses: impl IntoIterator<Item = BundledRuntimeProcessStatus>) -> Self {
            Self {
                statuses: statuses.into_iter().collect(),
                graceful_stop_requests: Rc::new(Cell::new(0)),
                termination_requests: Rc::new(Cell::new(0)),
                graceful_stop_outcomes: VecDeque::new(),
                wait_failures_remaining: 0,
                terminate_failures_remaining: 0,
            }
        }

        fn running() -> Self {
            Self::with_statuses([BundledRuntimeProcessStatus::Running])
        }

        fn exited() -> Self {
            Self::with_statuses([BundledRuntimeProcessStatus::Exited])
        }

        fn with_stop_tracking(
            statuses: impl IntoIterator<Item = BundledRuntimeProcessStatus>,
        ) -> (Self, Rc<Cell<u32>>, Rc<Cell<u32>>) {
            let graceful_stop_requests = Rc::new(Cell::new(0));
            let termination_requests = Rc::new(Cell::new(0));
            (
                Self {
                    statuses: statuses.into_iter().collect(),
                    graceful_stop_requests: Rc::clone(&graceful_stop_requests),
                    termination_requests: Rc::clone(&termination_requests),
                    graceful_stop_outcomes: VecDeque::new(),
                    wait_failures_remaining: 0,
                    terminate_failures_remaining: 0,
                },
                graceful_stop_requests,
                termination_requests,
            )
        }

        fn with_stop_failures(graceful_stop_fails: bool, wait_fails: bool) -> Self {
            Self {
                statuses: VecDeque::new(),
                graceful_stop_requests: Rc::new(Cell::new(0)),
                termination_requests: Rc::new(Cell::new(0)),
                graceful_stop_outcomes: VecDeque::from([graceful_stop_fails]),
                wait_failures_remaining: usize::from(wait_fails),
                terminate_failures_remaining: 0,
            }
        }

        fn with_termination_failure_once(
            statuses: impl IntoIterator<Item = BundledRuntimeProcessStatus>,
        ) -> (Self, Rc<Cell<u32>>) {
            let termination_requests = Rc::new(Cell::new(0));
            (
                Self {
                    statuses: statuses.into_iter().collect(),
                    graceful_stop_requests: Rc::new(Cell::new(0)),
                    termination_requests: Rc::clone(&termination_requests),
                    graceful_stop_outcomes: VecDeque::new(),
                    wait_failures_remaining: 0,
                    terminate_failures_remaining: 1,
                },
                termination_requests,
            )
        }

        fn with_wait_failure_once(
            statuses: impl IntoIterator<Item = BundledRuntimeProcessStatus>,
        ) -> Self {
            Self {
                statuses: statuses.into_iter().collect(),
                graceful_stop_requests: Rc::new(Cell::new(0)),
                termination_requests: Rc::new(Cell::new(0)),
                graceful_stop_outcomes: VecDeque::new(),
                wait_failures_remaining: 1,
                terminate_failures_remaining: 0,
            }
        }

        fn with_wait_failure_then_graceful_failure(
            statuses: impl IntoIterator<Item = BundledRuntimeProcessStatus>,
        ) -> Self {
            let mut process = Self::with_wait_failure_once(statuses);
            process.graceful_stop_outcomes = VecDeque::from([false, true]);
            process
        }
    }

    impl BundledRuntimeProcess for FakeProcess {
        fn status(&mut self) -> io::Result<BundledRuntimeProcessStatus> {
            Ok(self
                .statuses
                .pop_front()
                .unwrap_or(BundledRuntimeProcessStatus::Running))
        }

        fn request_graceful_stop(&mut self) -> io::Result<()> {
            self.graceful_stop_requests
                .set(self.graceful_stop_requests.get() + 1);
            if self.graceful_stop_outcomes.pop_front().unwrap_or(false) {
                return Err(io::Error::other("graceful stop failure"));
            }
            Ok(())
        }

        fn wait_for_exit(&mut self, _timeout: Duration) -> io::Result<BundledRuntimeProcessStatus> {
            if self.wait_failures_remaining > 0 {
                self.wait_failures_remaining -= 1;
                return Err(io::Error::other("wait failure"));
            }
            self.status()
        }

        fn terminate(&mut self) -> io::Result<()> {
            self.termination_requests
                .set(self.termination_requests.get() + 1);
            if self.terminate_failures_remaining > 0 {
                self.terminate_failures_remaining -= 1;
                return Err(io::Error::other("termination failure"));
            }
            Ok(())
        }
    }

    struct FakeLauncher {
        launches: Rc<Cell<u32>>,
        results: VecDeque<Result<FakeProcess, ()>>,
    }

    impl FakeLauncher {
        fn new(
            results: impl IntoIterator<Item = Result<FakeProcess, ()>>,
        ) -> (Self, Rc<Cell<u32>>) {
            let launches = Rc::new(Cell::new(0));
            (
                Self {
                    launches: Rc::clone(&launches),
                    results: results.into_iter().collect(),
                },
                launches,
            )
        }
    }

    impl BundledRuntimeProcessLauncher for FakeLauncher {
        type Process = FakeProcess;

        fn launch(&mut self, _spec: &BundledRuntimeLaunchSpec) -> io::Result<Self::Process> {
            self.launches.set(self.launches.get() + 1);
            self.results
                .pop_front()
                .unwrap_or(Err(()))
                .map_err(|()| io::Error::other("fake spawn failure"))
        }
    }

    #[cfg(not(windows))]
    fn absolute_test_executable() -> PathBuf {
        PathBuf::from("/opt/gocode/gocoded")
    }

    #[cfg(windows)]
    fn absolute_test_executable() -> PathBuf {
        PathBuf::from(r"C:\gocode\gocoded.exe")
    }

    fn launch_spec() -> BundledRuntimeLaunchSpec {
        BundledRuntimeLaunchSpec::new(
            absolute_test_executable(),
            BundledRuntimeLaunchMode::Direct,
            None,
        )
        .expect("valid launch spec")
        .with_profile_binding(BundledRuntimeProfileBinding::for_test(&runtime_identity()))
    }

    fn runtime_identity() -> BundledRuntimeAuthenticatedIdentity {
        BundledRuntimeAuthenticatedIdentity {
            profile_id: "gocode-ui-client/2".to_owned(),
            schema_hash: "a".repeat(64),
            authority_id: "0".repeat(32),
            principal_id: "desktop-development".to_owned(),
            event_log_lineage_id: "0199d55d-1a23-7000-8000-000000000001".to_owned(),
            daemon_instance_id: "0199d55d-1a23-7000-8000-000000000002".to_owned(),
            launch_generation: 1,
            session_id: "1".repeat(32),
            certificate_sha256: "b".repeat(64),
            capability_digest: "c".repeat(64),
        }
    }

    fn authenticated_handshake() -> BundledRuntimeAuthenticatedHandshake {
        BundledRuntimeAuthenticatedHandshake::for_test(runtime_identity())
    }

    fn prepare_next_profile_binding(
        supervisor: &mut BundledRuntimeSupervisor<FakeLauncher, FakeClock>,
        identity: &BundledRuntimeAuthenticatedIdentity,
    ) {
        supervisor.spec.profile_binding = Some(BundledRuntimeProfileBinding::for_test(identity));
    }

    #[cfg(unix)]
    pub struct OwnerPrivateBundledRuntimeFixture {
        root: tempfile::TempDir,
        desktop: PathBuf,
        daemon: PathBuf,
    }

    #[cfg(unix)]
    impl OwnerPrivateBundledRuntimeFixture {
        pub fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;

            let root = tempfile::Builder::new()
                .prefix("gocode-platform-desktop-")
                .tempdir_in("/tmp")
                .expect("create owner-private runtime fixture");
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("protect runtime fixture root");
            let desktop = root.path().join("gocode-desktop");
            let daemon = root.path().join("gocode-daemon");
            for executable in [&desktop, &daemon] {
                std::fs::write(executable, b"#!/bin/sh\nexit 0\n")
                    .expect("write controlled executable");
                std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o500))
                    .expect("protect controlled executable");
            }
            Self {
                root,
                desktop,
                daemon,
            }
        }

        pub fn desktop(&self) -> &std::path::Path {
            &self.desktop
        }

        pub fn daemon(&self) -> &std::path::Path {
            &self.daemon
        }

        pub fn runtime_root(&self) -> PathBuf {
            self.root.path().join("runtime")
        }
    }
