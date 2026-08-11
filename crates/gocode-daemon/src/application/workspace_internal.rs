//! Narrow workspace-only daemon startup entries.

use super::DaemonApplication;
use crate::error::DaemonError;
#[cfg(unix)]
use crate::protected_activation::VerifiedProtectedRuntimeStart;

pub(crate) mod provider_dependencies;

#[doc(hidden)]
pub use provider_dependencies::ProtectedProviderDependencyCapsule;

/// Starts the protected path after its authenticated launch verification.
///
/// The verified launch is opaque outside the daemon's protected activation API;
/// callers cannot select configuration, activation, provenance, or sender internals.
#[cfg(unix)]
pub async fn start_from_verified_protected_launch(
    verified_launch: VerifiedProtectedRuntimeStart,
    dependencies: ProtectedProviderDependencyCapsule,
) -> Result<DaemonApplication, DaemonError> {
    let (verified_launch, keys) = verified_launch.into_parts();
    DaemonApplication::start_protected(verified_launch, keys, dependencies).await
}

/// Starts the only external production source, selected inside the daemon.
pub async fn start_external_from_fixed_source(
    dependencies: ProtectedProviderDependencyCapsule,
) -> Result<DaemonApplication, DaemonError> {
    DaemonApplication::start_external_from_fixed_source(dependencies).await
}
