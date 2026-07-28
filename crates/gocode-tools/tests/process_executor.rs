use std::collections::HashMap;

use gocode_platform::containment::{
    ContainmentBackendId, ContainmentBackendVersion, ContainmentGate, ContainmentRequest,
    HostPlatform, RunnerIdentity, RuntimeProbe,
};
use gocode_security::broker::process::{
    CommandPolicy, LaunchedProcess, ProcessBroker, ProcessError, ProcessLauncher, ProcessSpec,
};
use gocode_tools::{
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

fn spec() -> ProcessSpec {
    ProcessSpec {
        executable: "/usr/bin/tool".into(),
        executable_digest: Some([7; 32]),
        argv: vec!["--version".into()],
        env: HashMap::new(),
        allowed_env_keys: Vec::new(),
        inherit_environment: false,
        cwd: "/workspace".into(),
        authorized_cwd: Some("/workspace".into()),
        cleanup_reservation_id: Some("cleanup-1".into()),
        worker_generation: 4,
        expected_generation: 4,
        timeout_ms: 1_000,
        command_policy: CommandPolicy::StructuredOnly,
    }
}

fn containment() -> ContainmentRequest {
    ContainmentRequest::new(
        ContainmentBackendId::new("native").unwrap(),
        ContainmentBackendVersion::new("1").unwrap(),
        HostPlatform::MacOs,
        RunnerIdentity::new("runner").unwrap(),
        vec![
            ContainmentGate::DirectEgressDenied,
            ContainmentGate::WorkspaceFilesystemConfined,
        ],
    )
    .unwrap()
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
    assert_eq!(
        result,
        Err(ProcessToolError::Broker(
            ProcessError::ContainmentUnavailable
        ))
    );
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
