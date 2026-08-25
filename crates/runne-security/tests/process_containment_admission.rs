mod process_containment_admission {
    use runne_platform::containment::{
        ContainmentBackendId, ContainmentBackendVersion, ContainmentGate, ContainmentRequest,
        HostPlatform, NativeCertificate, RunnerIdentity, RuntimeProbe,
    };
    use runne_platform_ports::process::{
        HeldFileIdentityV1, HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessFileKindV1,
        ProcessGenerationIdV1, ProcessLifecycleBindingV1, ProcessOwnerIdV1,
        ProcessPlatformRequestV1, ProcessSessionIdV1, ProcessSymlinkProofV1, VerifiedCwdV1,
        VerifiedExecutableV1,
    };
    use runne_security::broker::process::{
        CommandPolicy, OwnedProcessHandleV1, OwnerBoundProcessError,
        OwnerBoundProcessLaunchRequest, OwnerBoundProcessLauncher, OwnerBoundProcessRequest,
        ProcessBroker, ProcessInvocationIdV1, ProcessLaunchObservationV1, ProcessSpec,
    };
    use std::{
        collections::HashMap,
        sync::atomic::{AtomicUsize, Ordering},
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
    impl OwnerBoundProcessLauncher for RecordingLauncher {
        fn launch(
            &self,
            _: &OwnerBoundProcessLaunchRequest<'_>,
        ) -> Result<ProcessLaunchObservationV1, OwnerBoundProcessError> {
            self.launch_count.fetch_add(1, Ordering::SeqCst);
            ProcessLaunchObservationV1::new(41, [1; 32])
        }
        fn stop(&self, _: &OwnedProcessHandleV1) -> Result<(), OwnerBoundProcessError> {
            Ok(())
        }
    }

    fn broker() -> ProcessBroker {
        ProcessBroker::new(CommandPolicy::StructuredOnly)
    }
    fn virtual_executable() -> String {
        #[cfg(windows)]
        {
            r"C:\virtual\bin\tool.exe".into()
        }
        #[cfg(not(windows))]
        {
            "/virtual/bin/tool".into()
        }
    }
    fn virtual_cwd() -> String {
        #[cfg(windows)]
        {
            r"C:\virtual\workspace".into()
        }
        #[cfg(not(windows))]
        {
            "/virtual/workspace".into()
        }
    }
    fn valid_spec() -> ProcessSpec {
        let cwd = virtual_cwd();
        ProcessSpec {
            executable: virtual_executable(),
            executable_digest: Some([1; 32]),
            argv: vec!["--input".into(), "file.txt".into()],
            env: HashMap::new(),
            allowed_env_keys: Vec::new(),
            inherit_environment: false,
            cwd: cwd.clone(),
            authorized_cwd: Some(cwd),
            cleanup_reservation_id: Some("cleanup-1".into()),
            worker_generation: 1,
            expected_generation: 1,
            timeout_ms: 1_000,
            command_policy: CommandPolicy::StructuredOnly,
        }
    }
    fn binding() -> ProcessLifecycleBindingV1 {
        ProcessLifecycleBindingV1::new(
            ProcessOwnerIdV1::new([1; 16]).unwrap(),
            ProcessAttemptIdV1::new([2; 16]).unwrap(),
            ProcessSessionIdV1::new([3; 16]).unwrap(),
            ProcessGenerationIdV1::new([4; 16]).unwrap(),
            HeldProcessTreeHandleV1::new([5; 16]).unwrap(),
        )
    }
    fn prepared() -> ProcessPlatformRequestV1 {
        let executable = VerifiedExecutableV1::new(
            HeldFileIdentityV1::new([6; 16], [7; 32], [1; 32], [8; 32], 1).unwrap(),
            ProcessFileKindV1::RegularFile,
            ProcessSymlinkProofV1::VerifiedNotSymlink,
        )
        .unwrap();
        let cwd = VerifiedCwdV1::new(
            HeldFileIdentityV1::new([9; 16], [10; 32], [11; 32], [12; 32], 1).unwrap(),
            ProcessFileKindV1::Directory,
            ProcessSymlinkProofV1::VerifiedNotSymlink,
        )
        .unwrap();
        ProcessPlatformRequestV1::new([13; 32], executable, cwd).unwrap()
    }
    fn owner_request(spec: ProcessSpec) -> OwnerBoundProcessRequest {
        OwnerBoundProcessRequest::new_prepared(
            spec,
            prepared(),
            binding(),
            ProcessInvocationIdV1::new([14; 16]).unwrap(),
        )
        .unwrap()
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
    fn request() -> ContainmentRequest {
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
    fn certificate(platform: HostPlatform) -> NativeCertificate {
        NativeCertificate::new(
            ContainmentBackendId::new("native-containment").unwrap(),
            ContainmentBackendVersion::new("phase-6a").unwrap(),
            platform,
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
    fn probes(digest: &str) -> Vec<RuntimeProbe> {
        vec![RuntimeProbe::new("probe-a", digest).unwrap()]
    }
    fn launch(
        spec: ProcessSpec,
        certificate: Option<&NativeCertificate>,
        probes: &[RuntimeProbe],
    ) -> (
        Result<OwnedProcessHandleV1, OwnerBoundProcessError>,
        RecordingLauncher,
    ) {
        let launcher = RecordingLauncher::default();
        let result = broker().prepare_contained_owner_bound(
            owner_request(spec),
            &request(),
            certificate,
            probes,
            &launcher,
        );
        (result, launcher)
    }

    #[test]
    fn missing_certificate_returns_typed_error_without_launching() {
        let (error, launcher) = launch(valid_spec(), None, &probes("probe-digest"));
        assert_eq!(error, Err(OwnerBoundProcessError::ContainmentUnavailable));
        assert_eq!(launcher.launch_count(), 0);
    }
    #[test]
    fn mismatched_certificate_never_uses_unrestricted_fallback() {
        let certificate = certificate(other_platform());
        let (error, launcher) = launch(valid_spec(), Some(&certificate), &probes("probe-digest"));
        assert_eq!(error, Err(OwnerBoundProcessError::ContainmentUnavailable));
        assert_eq!(launcher.launch_count(), 0);
    }
    #[test]
    fn invalid_structured_argv_returns_validation_error_without_launching() {
        let mut spec = valid_spec();
        spec.argv.push("input;fallback".into());
        let (error, launcher) = launch(spec, None, &probes("probe-digest"));
        assert_eq!(error, Err(OwnerBoundProcessError::ProcessRejected));
        assert_eq!(launcher.launch_count(), 0);
    }
    #[test]
    fn stale_probe_returns_typed_error_without_launching() {
        let certificate = certificate(current_platform());
        let (error, launcher) = launch(valid_spec(), Some(&certificate), &probes("stale-digest"));
        assert_eq!(error, Err(OwnerBoundProcessError::ContainmentUnavailable));
        assert_eq!(launcher.launch_count(), 0);
    }
    #[test]
    fn matching_caller_constructed_certificate_is_unavailable_without_launching() {
        let certificate = certificate(current_platform());
        let (error, launcher) = launch(valid_spec(), Some(&certificate), &probes("probe-digest"));
        assert_eq!(error, Err(OwnerBoundProcessError::ContainmentUnavailable));
        assert_eq!(launcher.launch_count(), 0);
    }
}
