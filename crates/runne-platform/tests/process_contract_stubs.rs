use runne_platform::process_contract::{
    LinuxProcessPlatformPort, MacOsProcessPlatformPort, NATIVE_SANDBOX_STATUS,
    PROCESS_CONTRACT_STATUS, ProcessPlatformStubV1, ProcessPlatformTargetV1,
    UnsupportedProcessPlatformPort, WindowsProcessPlatformPort,
};
use runne_platform_ports::process::{
    HeldFileIdentityV1, HeldProcessTreeHandleV1, MonotonicDeadline, ProcessAttemptIdV1,
    ProcessFileKindV1, ProcessGenerationIdV1, ProcessLifecycleBindingV1, ProcessOwnerIdV1,
    ProcessPlatformFailure, ProcessPlatformPort, ProcessPlatformRequestV1, ProcessSessionIdV1,
    ProcessStubDisposition, ProcessSymlinkProofV1, VerifiedCwdV1, VerifiedExecutableV1,
};

#[test]
fn all_platform_stubs_fail_closed() {
    let request = request();
    let binding = binding();

    assert_eq!(PROCESS_CONTRACT_STATUS, "CONTRACT_ONLY");
    assert_eq!(NATIVE_SANDBOX_STATUS, "NATIVE_SANDBOX_NOT_QUALIFIED");
    assert_disposition(
        LinuxProcessPlatformPort,
        &request,
        &binding,
        ProcessStubDisposition::NotQualified,
    );
    assert_disposition(
        MacOsProcessPlatformPort,
        &request,
        &binding,
        ProcessStubDisposition::NotQualified,
    );
    assert_disposition(
        WindowsProcessPlatformPort,
        &request,
        &binding,
        ProcessStubDisposition::NotQualified,
    );
    assert_disposition(
        UnsupportedProcessPlatformPort,
        &request,
        &binding,
        ProcessStubDisposition::Unsupported,
    );
}

#[test]
fn target_selector_is_explicit_and_fail_closed() {
    let request = request();
    let binding = binding();

    let linux = ProcessPlatformStubV1::for_target(ProcessPlatformTargetV1::Linux);
    assert!(matches!(linux, ProcessPlatformStubV1::Linux(_)));
    assert_disposition(
        linux,
        &request,
        &binding,
        ProcessStubDisposition::NotQualified,
    );

    let macos = ProcessPlatformStubV1::for_target(ProcessPlatformTargetV1::Macos);
    assert!(matches!(macos, ProcessPlatformStubV1::Macos(_)));
    assert_disposition(
        macos,
        &request,
        &binding,
        ProcessStubDisposition::NotQualified,
    );

    let windows = ProcessPlatformStubV1::for_target(ProcessPlatformTargetV1::Windows);
    assert!(matches!(windows, ProcessPlatformStubV1::Windows(_)));
    assert_disposition(
        windows,
        &request,
        &binding,
        ProcessStubDisposition::NotQualified,
    );

    let other = ProcessPlatformStubV1::for_target(ProcessPlatformTargetV1::Other);
    assert!(matches!(other, ProcessPlatformStubV1::Unsupported(_)));
    assert_disposition(
        other,
        &request,
        &binding,
        ProcessStubDisposition::Unsupported,
    );
}

fn assert_disposition<P>(
    port: P,
    request: &ProcessPlatformRequestV1,
    binding: &ProcessLifecycleBindingV1,
    disposition: ProcessStubDisposition,
) where
    P: ProcessPlatformPort<Prepared = ()>,
{
    let expected = ProcessPlatformFailure::Disposition(disposition);

    let deadline = MonotonicDeadline::checked_after(1, 1).unwrap();
    assert_eq!(port.validate_and_prepare(request, deadline), Err(expected));
    assert_eq!(port.launch((), binding, deadline), Err(expected));
    assert_eq!(
        port.terminate(binding, MonotonicDeadline::checked_after(1, 1).unwrap()),
        Err(expected)
    );
}

fn request() -> ProcessPlatformRequestV1 {
    let executable = VerifiedExecutableV1::new(
        held_file_identity(1),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let cwd = VerifiedCwdV1::new(
        held_file_identity(2),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();

    ProcessPlatformRequestV1::new([3; 32], executable, cwd).unwrap()
}

fn held_file_identity(value: u8) -> HeldFileIdentityV1 {
    HeldFileIdentityV1::new([value; 16], [value; 32], [value; 32], [value; 32], 1).unwrap()
}

fn binding() -> ProcessLifecycleBindingV1 {
    ProcessLifecycleBindingV1::new(
        ProcessOwnerIdV1::new([4; 16]).unwrap(),
        ProcessAttemptIdV1::new([5; 16]).unwrap(),
        ProcessSessionIdV1::new([6; 16]).unwrap(),
        ProcessGenerationIdV1::new([7; 16]).unwrap(),
        HeldProcessTreeHandleV1::new([8; 16]).unwrap(),
    )
}
