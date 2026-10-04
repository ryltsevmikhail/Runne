#[cfg(any(
    all(test, unix),
    all(
        test,
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    )
))]
#[path = "../control_facade_tests/http_admission.rs"]
pub(super) mod http_admission_tests;

#[cfg(any(
    all(test, unix),
    all(
        test,
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    )
))]
#[path = "../control_facade_tests/protected_session.rs"]
pub(super) mod protected_session_tests;

#[cfg(any(
    all(test, unix),
    all(
        test,
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    )
))]
#[path = "../control_facade_tests/verify.rs"]
pub(super) mod verify_tests;

#[cfg(all(test, unix, feature = "desktop-protected"))]
pub(crate) use http_admission_tests::test_http_status_facts_available;
#[cfg(all(test, unix))]
pub(crate) use protected_session_tests::control as test_control;

#[cfg(all(test, target_os = "linux", feature = "desktop-protected"))]
#[path = "../control_facade_tests/http_background_route.rs"]
pub(super) mod http_background_route_tests;
