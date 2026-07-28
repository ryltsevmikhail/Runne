mod process_containment_admission {
    use std::{
        collections::HashMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use gocode_platform::containment::{
        ContainmentBackendId, ContainmentBackendVersion, ContainmentGate, ContainmentRequest,
        HostPlatform, NativeCertificate, RunnerIdentity, RuntimeProbe,
    };
    use gocode_security::broker::process::{
        CommandPolicy, LaunchedProcess, ProcessBroker, ProcessError, ProcessLauncher, ProcessSpec,
    };

    #[derive(Default)]
    struct RecordingLauncher {
        launch_count: AtomicUsize,
    }

    impl RecordingLauncher {
        fn launch_count(&self) -> usize {
            self.launch_count.load(Ordering::SeqCst)
        }
    }

    impl ProcessLauncher for RecordingLauncher {
        fn launch(&self, _spec: &ProcessSpec) -> Result<LaunchedProcess, ProcessError> {
            self.launch_count.fetch_add(1, Ordering::SeqCst);
            Ok(LaunchedProcess)
        }
    }

    fn broker() -> ProcessBroker {
        ProcessBroker::new(CommandPolicy::StructuredOnly)
    }

    fn valid_spec() -> ProcessSpec {
        ProcessSpec {
            executable: "/usr/bin/tool".into(),
            argv: vec!["--input".into(), "file.txt".into()],
            env: HashMap::new(),
            cwd: "/tmp".into(),
            command_policy: CommandPolicy::StructuredOnly,
        }
    }

    fn current_platform() -> HostPlatform {
        #[cfg(target_os = "linux")]
        {
            HostPlatform::Linux
        }
        #[cfg(target_os = "macos")]
        {
            HostPlatform::MacOs
        }
        #[cfg(target_os = "windows")]
        {
            HostPlatform::Windows
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            HostPlatform::Other("unsupported".into())
        }
    }

    fn current_platform_request() -> ContainmentRequest {
        ContainmentRequest::new(
            ContainmentBackendId::new("native-containment").unwrap(),
            ContainmentBackendVersion::new("phase-6a").unwrap(),
            current_platform(),
            RunnerIdentity::new("test-runner").unwrap(),
            vec![
                ContainmentGate::DirectEgressDenied,
                ContainmentGate::WorkspaceFilesystemConfined,
            ],
        )
        .unwrap()
    }

    fn wrong_platform_certificate() -> NativeCertificate {
        NativeCertificate::new(
            ContainmentBackendId::new("native-containment").unwrap(),
            ContainmentBackendVersion::new("phase-6a").unwrap(),
            other_platform(),
            RunnerIdentity::new("test-runner").unwrap(),
            "2026-07-27",
            "probe-digest",
            vec![
                ContainmentGate::DirectEgressDenied,
                ContainmentGate::WorkspaceFilesystemConfined,
            ],
        )
        .unwrap()
    }

    fn other_platform() -> HostPlatform {
        #[cfg(target_os = "linux")]
        {
            HostPlatform::MacOs
        }
        #[cfg(not(target_os = "linux"))]
        {
            HostPlatform::Linux
        }
    }

    fn matching_certificate() -> NativeCertificate {
        NativeCertificate::new(
            ContainmentBackendId::new("native-containment").unwrap(),
            ContainmentBackendVersion::new("phase-6a").unwrap(),
            current_platform(),
            RunnerIdentity::new("test-runner").unwrap(),
            "2026-07-27",
            "probe-digest",
            vec![
                ContainmentGate::DirectEgressDenied,
                ContainmentGate::WorkspaceFilesystemConfined,
            ],
        )
        .unwrap()
    }

    fn runtime_probes() -> Vec<RuntimeProbe> {
        vec![RuntimeProbe::new("probe-a", "probe-digest").unwrap()]
    }

    fn stale_runtime_probes() -> Vec<RuntimeProbe> {
        vec![RuntimeProbe::new("probe-a", "stale-digest").unwrap()]
    }

    #[test]
    fn missing_certificate_returns_typed_error_without_launching() {
        let launcher = RecordingLauncher::default();
        let error = broker()
            .prepare_contained(
                &valid_spec(),
                &current_platform_request(),
                None,
                &runtime_probes(),
                &launcher,
            )
            .unwrap_err();

        assert!(matches!(error, ProcessError::ContainmentUnavailable));
        assert_eq!(launcher.launch_count(), 0);
    }

    #[test]
    fn mismatched_certificate_never_uses_unrestricted_fallback() {
        let launcher = RecordingLauncher::default();
        let error = broker()
            .prepare_contained(
                &valid_spec(),
                &current_platform_request(),
                Some(&wrong_platform_certificate()),
                &runtime_probes(),
                &launcher,
            )
            .unwrap_err();

        assert!(matches!(error, ProcessError::ContainmentUnavailable));
        assert_eq!(launcher.launch_count(), 0);
    }

    #[test]
    fn invalid_structured_argv_returns_validation_error_without_launching() {
        let launcher = RecordingLauncher::default();
        let mut spec = valid_spec();
        spec.argv.push("input;fallback".into());

        let error = broker()
            .prepare_contained(
                &spec,
                &current_platform_request(),
                None,
                &runtime_probes(),
                &launcher,
            )
            .unwrap_err();

        assert!(matches!(error, ProcessError::ShellCommandForbidden));
        assert_eq!(launcher.launch_count(), 0);
    }

    #[test]
    fn stale_probe_returns_typed_error_without_launching() {
        let launcher = RecordingLauncher::default();
        let error = broker()
            .prepare_contained(
                &valid_spec(),
                &current_platform_request(),
                Some(&matching_certificate()),
                &stale_runtime_probes(),
                &launcher,
            )
            .unwrap_err();

        assert!(matches!(error, ProcessError::ContainmentUnavailable));
        assert_eq!(launcher.launch_count(), 0);
    }

    #[test]
    fn matching_caller_constructed_certificate_is_unavailable_without_launching() {
        let launcher = RecordingLauncher::default();

        let error = broker()
            .prepare_contained(
                &valid_spec(),
                &current_platform_request(),
                Some(&matching_certificate()),
                &runtime_probes(),
                &launcher,
            )
            .unwrap_err();

        assert!(matches!(error, ProcessError::ContainmentUnavailable));
        assert_eq!(launcher.launch_count(), 0);
    }
}
