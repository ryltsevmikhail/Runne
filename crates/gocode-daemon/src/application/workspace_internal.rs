//! Narrow workspace-only daemon startup entries.

#[cfg(all(unix, feature = "desktop-protected"))]
use super::DaemonApplication;
#[cfg(all(unix, feature = "desktop-protected"))]
use crate::error::DaemonError;
#[cfg(all(unix, feature = "desktop-protected"))]
use crate::protected_activation::VerifiedProtectedRuntimeStart;

mod provider_dependencies;

pub use provider_dependencies::LoopbackCredentialVersionStoreFactory;
pub(crate) use provider_dependencies::ProtectedProviderDependencyCapsule;
pub(crate) use provider_dependencies::ProviderDependencyState;

/// Starts the protected path after its authenticated launch verification.
///
/// The verified launch is opaque outside the daemon's protected activation API;
/// callers cannot select configuration, activation, provenance, or sender internals.
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) async fn start_from_verified_protected_launch(
    verified_launch: VerifiedProtectedRuntimeStart,
    dependencies: ProtectedProviderDependencyCapsule,
) -> Result<DaemonApplication, DaemonError> {
    let (verified_launch, keys) = verified_launch.into_parts();
    DaemonApplication::start_protected(verified_launch, keys, dependencies).await
}
