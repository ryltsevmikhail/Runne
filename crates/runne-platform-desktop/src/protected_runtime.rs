// Native implementations are target-gated below; unsupported platforms fail
// closed without exporting a renderer-visible fallback.
#![cfg_attr(
    not(any(unix, windows)),
    allow(dead_code, clippy::missing_const_for_fn)
)]

include!("protected_runtime/state_records.rs");
include!("protected_runtime/state_store.rs");
include!("protected_runtime/launcher.rs");
include!("protected_runtime/writer_staging.rs");
include!("protected_runtime/process.rs");
#[cfg(test)]
include!("protected_runtime/provider_readiness_tests.rs");
include!("protected_runtime/supervisor.rs");
include!("protected_runtime/helpers.rs");
include!("protected_runtime/native_enrollment.rs");
include!("protected_runtime/tests.rs");
#[cfg(test)]
include!("protected_runtime/native_enrollment_tests.rs");
include!("protected_runtime/renewal.rs");
include!("protected_runtime/enrollment_transition.rs");
#[cfg(all(test, unix))]
include!("protected_runtime/enrollment_transition_tests.rs");
#[cfg(feature = "test-support")]
include!("protected_runtime/test_root_transport.rs");
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
