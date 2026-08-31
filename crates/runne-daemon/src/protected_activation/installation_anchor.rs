#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub(crate) use macos::VerifiedNativeEnrollmentInstallation;
#[cfg(target_os = "macos")]
pub(crate) use macos::load_read_only;
#[cfg(target_os = "macos")]
pub(super) use macos::provision_after_provider_bound_v2;
#[cfg(all(test, target_os = "macos"))]
pub(super) use macos::test_guard;
#[cfg(all(test, target_os = "macos"))]
pub(super) use macos::{Fault, set_fault};
