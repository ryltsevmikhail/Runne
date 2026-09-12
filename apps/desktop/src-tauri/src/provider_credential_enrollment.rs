//! Native-only credential enrollment host state. Step 5 owns daemon orchestration.

mod command;
mod dispatch;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod host_prompt;
pub mod intent;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod prepared;
mod projection;
mod status;
pub(crate) use status::load_status;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[path = "provider_credential_enrollment/prepared/reap_guard.rs"]
mod reap_guard;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[path = "provider_credential_enrollment/prepared/reaper_registry.rs"]
mod reaper_registry;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod service_registration;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use prepared::reconcile_startup;

pub use command::CredentialIntentIpc;
pub use intent::CredentialIntentRegistry;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use prepared::ProtectedWriterReaperRegistry;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub type ProtectedWriterReaperRegistry =
    reaper_registry::CredentialWriterReaperRegistry<UnsupportedWriterCleanup>;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use prepared::{
    CredentialWriterReaperLastError, CredentialWriterReaperSnapshot, CredentialWriterReaperState,
};
pub use projection::CredentialIntentProjection;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub use reaper_registry::{
    CredentialWriterReaperLastError, CredentialWriterReaperSnapshot, CredentialWriterReaperState,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use service_registration::{
    CredentialServiceRegistration, CredentialServiceRegistrationDisposition,
};

pub use dispatch::dispatch_credential_intent;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub struct UnsupportedWriterCleanup;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
impl reap_guard::ExactWriterCleanup for UnsupportedWriterCleanup {
    type Error = ();

    fn finish_exact(&mut self) -> Result<(), Self::Error> {
        Err(())
    }

    fn abort_exact(&mut self) -> Result<(), Self::Error> {
        Err(())
    }
}
