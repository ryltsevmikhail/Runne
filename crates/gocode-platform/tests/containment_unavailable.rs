use gocode_platform::{
    AttestationVerdict, ContainmentBackendId, ContainmentBackendVersion, ContainmentError,
    ContainmentGate, ContainmentRequest, HostPlatform, NativeCertificate, RunnerIdentity,
    RuntimeProbe, StartupAttestor,
};

#[test]
fn absent_certificate_is_unavailable() {
    let request = containment_request_for_current_platform();
    assert_eq!(
        StartupAttestor::attest(&request, None, &runtime_probes()),
        Err(ContainmentError::BackendUnavailable),
    );
}

#[test]
fn certificate_with_wrong_platform_is_unavailable() {
    let request = containment_request_for_current_platform();
    let certificate = native_certificate_for(HostPlatform::Other("wrong".into()));
    assert_eq!(
        StartupAttestor::attest(&request, Some(&certificate), &runtime_probes()),
        Err(ContainmentError::BackendUnavailable),
    );
}

#[test]
fn empty_other_platform_is_rejected_as_backend_unavailable() {
    assert_eq!(
        containment_request_result_for(HostPlatform::Other(String::new())),
        Err(ContainmentError::BackendUnavailable),
    );
    assert_eq!(
        native_certificate_result_for(HostPlatform::Other(String::new())),
        Err(ContainmentError::BackendUnavailable),
    );
}

#[test]
fn overlong_other_platform_is_rejected_as_backend_unavailable() {
    let overlong_platform = HostPlatform::Other("x".repeat(257));
    assert_eq!(
        containment_request_result_for(overlong_platform.clone()),
        Err(ContainmentError::BackendUnavailable),
    );
    assert_eq!(
        native_certificate_result_for(overlong_platform),
        Err(ContainmentError::BackendUnavailable),
    );
}

#[test]
fn duplicate_or_unsorted_covered_gates_are_rejected() {
    assert!(
        NativeCertificate::new(
            backend_id(),
            backend_version(),
            current_platform(),
            runner_id(),
            qualification_date(),
            evidence_digest(),
            vec![
                ContainmentGate::DirectEgressDenied,
                ContainmentGate::DirectEgressDenied
            ],
        )
        .is_err()
    );
    assert!(
        NativeCertificate::new(
            backend_id(),
            backend_version(),
            current_platform(),
            runner_id(),
            qualification_date(),
            evidence_digest(),
            vec![
                ContainmentGate::WorkspaceFilesystemConfined,
                ContainmentGate::DirectEgressDenied
            ],
        )
        .is_err()
    );
}

#[test]
fn certificate_with_wrong_backend_version_is_unavailable() {
    let request = containment_request_for_current_platform();
    let certificate = NativeCertificate::new(
        backend_id(),
        ContainmentBackendVersion::new("wrong-version").unwrap(),
        current_platform(),
        runner_id(),
        qualification_date(),
        evidence_digest(),
        requested_gates(),
    )
    .unwrap();
    assert_eq!(
        StartupAttestor::attest(&request, Some(&certificate), &runtime_probes()),
        Err(ContainmentError::BackendUnavailable),
    );
}

#[test]
fn certificate_with_changed_runner_identity_is_unavailable() {
    let request = containment_request_for_current_platform();
    let certificate = NativeCertificate::new(
        backend_id(),
        backend_version(),
        current_platform(),
        RunnerIdentity::new("other-runner").unwrap(),
        qualification_date(),
        evidence_digest(),
        requested_gates(),
    )
    .unwrap();
    assert_eq!(
        StartupAttestor::attest(&request, Some(&certificate), &runtime_probes()),
        Err(ContainmentError::BackendUnavailable),
    );
}

#[test]
fn certificate_missing_required_gate_is_unavailable() {
    let request = containment_request_for_current_platform();
    let certificate = NativeCertificate::new(
        backend_id(),
        backend_version(),
        current_platform(),
        runner_id(),
        qualification_date(),
        evidence_digest(),
        vec![ContainmentGate::DirectEgressDenied],
    )
    .unwrap();
    assert_eq!(
        StartupAttestor::attest(&request, Some(&certificate), &runtime_probes()),
        Err(ContainmentError::BackendUnavailable),
    );
}

#[test]
fn stale_probe_is_unavailable() {
    let request = containment_request_for_current_platform();
    let certificate = native_certificate_for(current_platform());
    let stale_probes = vec![RuntimeProbe::new("kernel", "stale-digest").unwrap()];
    assert_eq!(
        StartupAttestor::attest(&request, Some(&certificate), &stale_probes),
        Err(ContainmentError::BackendUnavailable),
    );
}

#[test]
fn matching_certificate_verdict_is_platform_specific() {
    let request = containment_request_for_current_platform();
    let certificate = native_certificate_for(current_platform());
    #[cfg(target_os = "linux")]
    assert_eq!(
        StartupAttestor::attest(&request, Some(&certificate), &runtime_probes()),
        Ok(AttestationVerdict::Permit),
    );
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        StartupAttestor::attest(&request, Some(&certificate), &runtime_probes()),
        Ok(AttestationVerdict::Unavailable),
    );
}

#[cfg(target_os = "linux")]
#[test]
fn platform_backend_yields_permit_for_valid_certificate() {
    use gocode_platform::containment::linux;
    let runner = RunnerIdentity::new("test-runner").unwrap();
    let gates = vec![
        ContainmentGate::DirectEgressDenied,
        ContainmentGate::WorkspaceFilesystemConfined,
    ];
    let certificate = linux::native_certificate(runner.clone(), gates.clone()).unwrap();
    let request = ContainmentRequest::new(
        ContainmentBackendId::new("gocode-native-linux").unwrap(),
        ContainmentBackendVersion::new("0.1.0").unwrap(),
        HostPlatform::Linux,
        runner,
        gates,
    )
    .unwrap();
    assert_eq!(
        linux::LinuxContainment::attest(&request, Some(&certificate), &linux::runtime_probes()),
        Ok(AttestationVerdict::Permit),
    );
}

#[cfg(target_os = "macos")]
#[test]
fn platform_backend_is_unconditionally_unavailable() {
    use gocode_platform::containment::macos;
    assert_eq!(
        macos::MacOsContainment::attest(
            &containment_request_for_current_platform(),
            Some(&native_certificate_for(current_platform())),
            &runtime_probes(),
        ),
        Err(ContainmentError::BackendUnavailable),
    );
}

#[cfg(target_os = "windows")]
#[test]
fn platform_backend_is_unconditionally_unavailable() {
    use gocode_platform::containment::windows;
    assert_eq!(
        windows::WindowsContainment::attest(
            &containment_request_for_current_platform(),
            Some(&native_certificate_for(current_platform())),
            &runtime_probes(),
        ),
        Err(ContainmentError::BackendUnavailable),
    );
}

fn containment_request_for_current_platform() -> ContainmentRequest {
    containment_request_result_for(current_platform()).unwrap()
}

fn containment_request_result_for(
    platform: HostPlatform,
) -> Result<ContainmentRequest, ContainmentError> {
    ContainmentRequest::new(
        backend_id(),
        backend_version(),
        platform,
        runner_id(),
        requested_gates(),
    )
}

fn native_certificate_for(platform: HostPlatform) -> NativeCertificate {
    native_certificate_result_for(platform).unwrap()
}

fn native_certificate_result_for(
    platform: HostPlatform,
) -> Result<NativeCertificate, ContainmentError> {
    NativeCertificate::new(
        backend_id(),
        backend_version(),
        platform,
        runner_id(),
        qualification_date(),
        evidence_digest(),
        requested_gates(),
    )
}

fn backend_id() -> ContainmentBackendId {
    ContainmentBackendId::new("native-backend").unwrap()
}

fn backend_version() -> ContainmentBackendVersion {
    ContainmentBackendVersion::new("1.0.0").unwrap()
}

fn runner_id() -> RunnerIdentity {
    RunnerIdentity::new("runner-a").unwrap()
}

fn qualification_date() -> String {
    "2026-07-27".into()
}

fn evidence_digest() -> String {
    "probe-digest".into()
}

fn requested_gates() -> Vec<ContainmentGate> {
    vec![
        ContainmentGate::DirectEgressDenied,
        ContainmentGate::WorkspaceFilesystemConfined,
    ]
}

fn runtime_probes() -> Vec<RuntimeProbe> {
    vec![RuntimeProbe::new("kernel", "probe-digest").unwrap()]
}

#[cfg(target_os = "linux")]
fn current_platform() -> HostPlatform {
    HostPlatform::Linux
}

#[cfg(target_os = "macos")]
fn current_platform() -> HostPlatform {
    HostPlatform::MacOs
}

#[cfg(target_os = "windows")]
fn current_platform() -> HostPlatform {
    HostPlatform::Windows
}
