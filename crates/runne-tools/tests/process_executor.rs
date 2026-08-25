use std::collections::HashMap;

use runne_platform::containment::{
    ContainmentBackendId, ContainmentBackendVersion, ContainmentGate, ContainmentRequest,
    HostPlatform, RunnerIdentity, RuntimeProbe,
};
use runne_platform_ports::process::{
    HeldFileIdentityV1, HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessFileKindV1,
    ProcessGenerationIdV1, ProcessLifecycleBindingV1, ProcessOwnerIdV1, ProcessPlatformRequestV1,
    ProcessSessionIdV1, ProcessSymlinkProofV1, VerifiedCwdV1, VerifiedExecutableV1,
};
use runne_security::broker::process::{
    CommandPolicy, LaunchedProcess, OwnedProcessHandleV1, OwnerBoundProcessError,
    OwnerBoundProcessLaunchRequest, OwnerBoundProcessLauncher, OwnerBoundProcessRequest,
    ProcessBroker, ProcessError, ProcessInvocationIdV1, ProcessLaunchObservationV1,
    ProcessLauncher, ProcessSpec,
};
use runne_tools::{
    ProcessLifecycleReport, ProcessOperation, ProcessStartRequest, ProcessToolError,
    ProcessToolExecutor,
};

#[derive(Default)]
struct PanicLauncher;

impl ProcessLauncher for PanicLauncher {
    fn launch(&self, _spec: &ProcessSpec) -> Result<LaunchedProcess, ProcessError> {
        panic!("launcher must remain untouched without certified containment")
    }
}

impl OwnerBoundProcessLauncher for PanicLauncher {
    fn launch(
        &self,
        _request: &OwnerBoundProcessLaunchRequest<'_>,
    ) -> Result<ProcessLaunchObservationV1, OwnerBoundProcessError> {
        panic!("owner launcher must remain untouched without certified containment")
    }

    fn stop(&self, _handle: &OwnedProcessHandleV1) -> Result<(), OwnerBoundProcessError> {
        panic!("owner stopper must remain untouched without a live launch")
    }
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

fn spec() -> ProcessSpec {
    let cwd = virtual_cwd();
    ProcessSpec {
        executable: virtual_executable(),
        executable_digest: Some([7; 32]),
        argv: vec!["--version".into()],
        env: HashMap::new(),
        allowed_env_keys: Vec::new(),
        inherit_environment: false,
        cwd: cwd.clone(),
        authorized_cwd: Some(cwd),
        cleanup_reservation_id: Some("cleanup-1".into()),
        worker_generation: 4,
        expected_generation: 4,
        timeout_ms: 1_000,
        command_policy: CommandPolicy::StructuredOnly,
    }
}

fn containment() -> ContainmentRequest {
    #[cfg(target_os = "linux")]
    let platform = HostPlatform::Linux;
    #[cfg(target_os = "macos")]
    let platform = HostPlatform::MacOs;
    #[cfg(target_os = "windows")]
    let platform = HostPlatform::Windows;
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let platform = HostPlatform::Other("unsupported".into());

    ContainmentRequest::new(
        ContainmentBackendId::new("native").unwrap(),
        ContainmentBackendVersion::new("1").unwrap(),
        platform,
        RunnerIdentity::new("runner").unwrap(),
        vec![
            ContainmentGate::DirectEgressDenied,
            ContainmentGate::WorkspaceFilesystemConfined,
        ],
    )
    .unwrap()
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
        HeldFileIdentityV1::new([9; 16], [1; 32], [7; 32], [2; 32], 1).unwrap(),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let cwd = VerifiedCwdV1::new(
        HeldFileIdentityV1::new([8; 16], [3; 32], [4; 32], [5; 32], 1).unwrap(),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    ProcessPlatformRequestV1::new([6; 32], executable, cwd).unwrap()
}

#[test]
fn process_executor_never_bypasses_unavailable_containment() {
    let executor = ProcessToolExecutor::new(ProcessBroker::new(CommandPolicy::StructuredOnly));
    let spec = spec();
    let containment = containment();
    let probes = [RuntimeProbe::new("probe", "digest").unwrap()];
    let result = executor.start(
        ProcessStartRequest {
            operation: ProcessOperation::Exec,
            spec: &spec,
            containment: &containment,
            certificate: None,
            probes: &probes,
        },
        &PanicLauncher,
    );
    assert_eq!(result, Err(ProcessToolError::OwnerBoundRequired));
}

#[test]
fn selected_pty_is_explicitly_unavailable() {
    let executor = ProcessToolExecutor::new(ProcessBroker::new(CommandPolicy::StructuredOnly));
    let spec = spec();
    let containment = containment();
    assert_eq!(
        executor.start(
            ProcessStartRequest {
                operation: ProcessOperation::Pty,
                spec: &spec,
                containment: &containment,
                certificate: None,
                probes: &[],
            },
            &PanicLauncher,
        ),
        Err(ProcessToolError::PtyBackendUnavailable)
    );
}

#[test]
fn owner_bound_executor_never_bypasses_unavailable_containment() {
    let executor = ProcessToolExecutor::new(ProcessBroker::new(CommandPolicy::StructuredOnly));
    let request = OwnerBoundProcessRequest::new_prepared(
        spec(),
        prepared(),
        binding(),
        ProcessInvocationIdV1::new([6; 16]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        executor.start_owner_bound(request, &containment(), None, &[], &PanicLauncher),
        Err(ProcessToolError::OwnerBound(
            OwnerBoundProcessError::ContainmentUnavailable
        ))
    );
}

#[test]
fn lifecycle_rejects_stale_generation_and_remaining_descendants() {
    let stale = ProcessLifecycleReport {
        observed_generation: 3,
        ..ProcessLifecycleReport::default()
    };
    assert_eq!(
        ProcessToolExecutor::close_material(4, stale),
        Err(ProcessToolError::StaleGeneration)
    );

    let descendants = ProcessLifecycleReport {
        observed_generation: 4,
        remaining_descendants: 1,
        ..ProcessLifecycleReport::default()
    };
    assert_eq!(
        ProcessToolExecutor::close_material(4, descendants),
        Err(ProcessToolError::DescendantsRemain)
    );
}

#[test]
fn lifecycle_preserves_timeout_cancel_and_exact_cleanup_evidence() {
    let material = ProcessToolExecutor::close_material(
        4,
        ProcessLifecycleReport {
            process_terminal: true,
            containment_released: true,
            cleanup_closed: false,
            timed_out: true,
            cancelled: true,
            observed_generation: 4,
            ..ProcessLifecycleReport::default()
        },
    )
    .unwrap();
    assert!(material.evidence.process_terminal);
    assert!(material.evidence.containment_released);
    assert!(!material.evidence.cleanup_closed);
    assert!(material.timed_out);
    assert!(material.cancelled);
}
