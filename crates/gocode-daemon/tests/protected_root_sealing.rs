#![cfg(feature = "desktop-protected")]

const ADMISSION: &str = include_str!("../src/application/root_handle_admission.rs");
const READINESS: &str = include_str!("../src/application/readiness.rs");
const ACTIVATION: &str = include_str!("../src/protected_activation.rs");
const CONTROL: &str = include_str!("../src/protected_activation/root_handle_control.rs");

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
}
