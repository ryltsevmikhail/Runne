#![cfg(feature = "desktop-protected")]

const ADMISSION: &str = include_str!("../src/application/root_handle_admission.rs");
const APPLICATION: &str = include_str!("../src/application.rs");
const READINESS: &str = include_str!("../src/application/readiness.rs");
const ACTIVATION: &str = include_str!("../src/protected_activation.rs");
const CONTROL: &str = include_str!("../src/protected_activation/root_handle_control.rs");
const HARNESS: &str = include_str!("../src/application/root_admission_test_support.rs");
const LAUNCH: &str = include_str!("../src/protected_activation/launch.rs");
const WORKSPACE: &str = include_str!("../src/application/workspace_internal.rs");
const TEST_SUPPORT: &str = include_str!("../src/protected_activation/test_support.rs");
const HOST: &str = include_str!("../src/protected_activation/host.rs");
const DEPENDENCIES: &str =
    include_str!("../src/application/workspace_internal/provider_dependencies.rs");

#[test]
fn root_admission_issuer_and_dispatcher_remain_daemon_internal() {
    for sealed in [
        "pub(crate) struct RootHandleAdmissionAuthority",
        "pub(crate) struct RootAdmissionGateway",
        "pub(crate) fn protected_root_control",
        "pub(crate) use root_handle_control::dispatch_root_handle_control_frame",
        "pub(crate) fn dispatch_root_handle_control_frame",
    ] {
        let source = match sealed {
            value if value.contains("Authority") || value.contains("Gateway") => ADMISSION,
            value if value.contains("protected_root_control") => READINESS,
            value if value.contains("use root_handle") => ACTIVATION,
            _ => CONTROL,
        };
        assert!(
            source.contains(sealed),
            "missing sealed declaration: {sealed}"
        );
    }
    for exposed in [
        "pub struct RootHandleAdmissionAuthority",
        "pub struct RootAdmissionGateway",
        "pub fn protected_root_control",
        "pub fn dispatch_root_handle_control_frame",
    ] {
        assert!(!ADMISSION.contains(exposed));
        assert!(!READINESS.contains(exposed));
        assert!(!CONTROL.contains(exposed));
    }
    assert!(APPLICATION.contains("pub(crate) mod root_admission_test_support"));
    assert!(!APPLICATION.contains("pub mod root_admission_test_support"));
    for exposed in [
        "pub struct RootAdmissionHarness",
        "pub fn new(",
        "pub fn admit(",
        "pub fn fence(",
    ] {
        assert!(!HARNESS.contains(exposed), "test issuer exposed: {exposed}");
    }
}

#[test]
fn protected_launch_and_test_controls_remain_sealed() {
    for sealed in [
        "pub(crate) struct ProtectedDaemonLaunch",
        "pub(crate) fn accept",
        "pub(crate) mod workspace_internal",
        "pub(crate) async fn start_from_verified_protected_launch",
        "pub(crate) fn protected_ready",
        "pub(crate) fn protected_session_service",
        "pub(crate) fn protected_session_clock",
        "pub(crate) fn dispatch_without_admission",
        "pub(crate) fn run_without_admission",
    ] {
        let source = if sealed.contains("DaemonLaunch") || sealed.contains("accept") {
            LAUNCH
        } else if sealed.contains("workspace") || sealed.contains("start_from") {
            if sealed.contains("workspace") {
                APPLICATION
            } else {
                WORKSPACE
            }
        } else if sealed.contains("protected_") {
            READINESS
        } else {
            TEST_SUPPORT
        };
        assert!(
            source.contains(sealed),
            "missing sealed declaration: {sealed}"
        );
    }
    for exposed in [
        "pub struct ProtectedDaemonLaunch",
        "pub fn accept",
        "pub mod workspace_internal",
        "pub async fn start_from_verified_protected_launch",
        "pub fn protected_ready",
        "pub fn protected_session_service",
        "pub fn protected_session_clock",
        "pub fn dispatch_without_admission",
        "pub fn run_without_admission",
    ] {
        assert!(!LAUNCH.contains(exposed));
        assert!(!APPLICATION.contains(exposed));
        assert!(!WORKSPACE.contains(exposed));
        assert!(!READINESS.contains(exposed));
        assert!(!TEST_SUPPORT.contains(exposed));
    }
    assert!(HOST.contains("pub(crate) fn run_verified_protected_channel_with_fixture"));
    assert!(!ACTIVATION.contains("pub use launch::ProtectedDaemonLaunch"));
}

#[test]
fn loopback_qualification_keeps_provider_dependencies_internal() {
    for sealed in [
        "pub(crate) fn run_verified_protected_channel_with_fixture",
        "pub(crate) struct ProtectedProviderDependencyCapsule",
        "pub(crate) const fn production",
        "pub(crate) fn from_loopback_fixture",
    ] {
        let source = if sealed.contains("run_verified") {
            HOST
        } else {
            DEPENDENCIES
        };
        assert!(
            source.contains(sealed),
            "missing sealed declaration: {sealed}"
        );
    }
    for exposed in [
        "pub fn run_verified_protected_channel_with_fixture",
        "pub struct ProtectedProviderDependencyCapsule",
        "pub const fn production",
        "pub fn from_loopback_fixture",
        "pub use crate::application::workspace_internal::ProtectedProviderDependencyCapsule",
    ] {
        assert!(!ACTIVATION.contains(exposed));
        assert!(!HOST.contains(exposed));
        assert!(!DEPENDENCIES.contains(exposed));
    }
    assert!(TEST_SUPPORT.contains("pub fn run_loopback_inherited_fixture()"));
    assert!(!TEST_SUPPORT.contains("runtime_root"));
    assert!(!TEST_SUPPORT.contains("ProtectedProviderDependencyCapsule"));
}
