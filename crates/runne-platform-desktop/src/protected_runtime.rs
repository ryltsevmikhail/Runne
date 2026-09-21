// Native implementations are target-gated below; unsupported platforms fail
// closed without exporting a renderer-visible fallback.
#![cfg_attr(
    not(any(unix, windows)),
    allow(dead_code, clippy::missing_const_for_fn)
)]

include!("protected_runtime/state_records.rs");
include!("protected_runtime/state_store.rs");
include!("protected_runtime/launcher.rs");
include!("protected_runtime/activation_rebind.rs");
#[cfg(unix)]
include!("protected_runtime/local_process_fixture.rs");
include!("protected_runtime/writer_staging.rs");
include!("protected_runtime/process.rs");
#[cfg(test)]
include!("protected_runtime/provider_readiness_tests.rs");
include!("protected_runtime/supervisor.rs");
include!("protected_runtime/launch_unix.rs");
include!("protected_runtime/helpers.rs");
include!("protected_runtime/native_enrollment.rs");
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "protected-channel-integration"
))]
mod enrollment_status;
#[cfg(target_os = "macos")]
include!("protected_runtime/native_confirmation.rs");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod enrollment_lifecycle_facts;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod enrollment_lifecycle_types;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use enrollment_lifecycle_types::{
    NativeProtectedCredentialEnrollmentBegin, NativeProtectedCredentialVerificationBegin,
    PreparedProtectedCredentialEnrollment, PreparedProtectedCredentialVerification,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
include!("protected_runtime/enrollment_lifecycle.rs");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
include!("protected_runtime/enrollment_verification.rs");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod cleanup_recovery;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod control_response;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod credential_discovery;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod qualification_relay;
#[cfg(all(feature = "test-support", target_os = "macos", target_arch = "aarch64"))]
pub use credential_discovery::{
    test_only_crossed_discovery, test_only_crossed_renewal, test_only_crossed_round,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod credential_round;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod enrollment_terminal;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod shutdown_interleaved;
#[cfg(all(feature = "test-support", target_os = "macos", target_arch = "aarch64"))]
pub use shutdown_interleaved::test_only_crossed_shutdown;
#[cfg(all(
    test,
    feature = "test-support",
    target_os = "macos",
    target_arch = "aarch64"
))]
mod shutdown_tests;
#[cfg(all(feature = "test-support", target_os = "macos", target_arch = "aarch64"))]
pub use enrollment_terminal::test_only_pair_terminal;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod renewal_interleaved;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use cleanup_recovery::PreparedProtectedCredentialRecovery;
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
include!("protected_runtime/enrollment_lifecycle_tests.rs");
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod qualification_relay_tests;
include!("protected_runtime/tests.rs");
#[cfg(all(test, unix))]
include!("protected_runtime/native_enrollment_tests.rs");
include!("protected_runtime/renewal.rs");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
include!("protected_runtime/enrollment_transition.rs");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
include!("protected_runtime/enrollment_broker_handoff.rs");
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "protected-channel-integration"
))]
mod broker_driver;
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "protected-channel-integration",
    feature = "test-support"
))]
pub use broker_driver::test_only_crossed_broker_offer;
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "protected-channel-integration"
))]
mod broker_offer;
#[cfg(target_os = "macos")]
mod handoff_failure;
#[cfg(target_os = "macos")]
pub use handoff_failure::CredentialWriterHandoffError;
#[cfg(all(target_os = "macos", feature = "test-support"))]
pub use handoff_failure::test_only_failed_writer_handoff;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod credential_service_session;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use credential_service_session::{
    PreparedCredentialServiceRejoin, PreparedCredentialServiceSessionRegistration,
    RegisteredCredentialServiceSession,
};
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod credential_service_session_tests;
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
include!("protected_runtime/enrollment_transition_tests.rs");
#[cfg(feature = "test-support")]
include!("protected_runtime/test_root_transport.rs");
#[cfg(all(feature = "test-support", target_os = "macos", target_arch = "aarch64"))]
include!("protected_runtime/test_enrollment_fixture.rs");
include!("protected_runtime/root_handle_transport.rs");
#[cfg(windows)]
include!("protected_runtime/windows_channel.rs");
#[cfg(windows)]
include!("protected_runtime/windows_store.rs");
#[cfg(windows)]
include!("protected_runtime/windows_launcher.rs");
#[cfg(windows)]
include!("protected_runtime/windows_fs.rs");
#[cfg(windows)]
include!("protected_runtime/windows_security.rs");
#[cfg(windows)]
include!("protected_runtime/windows_job.rs");
include!("protected_runtime/supervisor_root_admission.rs");
include!("protected_runtime_parts/port_08.rs");
include!("protected_runtime_parts/port_09.rs");
include!("protected_runtime_parts/port_10.rs");
include!("protected_runtime_parts/port_11.rs");
