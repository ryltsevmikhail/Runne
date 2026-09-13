#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::path::PathBuf;
use std::path::Path;

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
use super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod measurement_facts;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use measurement_facts::{
    QualificationAdmissionError, VerifiedInstalledEnrollmentMeasurementFacts,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "daemon_installed/capability.rs"]
mod capability;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "daemon_installed/bootstrap_candidate.rs"]
mod bootstrap_candidate;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "daemon_installed/staged_identity.rs"]
mod staged_identity;
#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
include!("daemon_installed/verification.rs");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use capability::VerifiedInstalledEnrollmentCapability;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use bootstrap_candidate::{
    VerifiedInstalledQualificationBootstrapCandidate, VerifiedRuntimeQualificationAcknowledgement,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use staged_identity::CurrentStagedDaemonIdentity;

/// Opaque evidence bound to one exact daemon prepare claim.
///
/// The evidence is move-only so one verification cannot authorize two prepares.
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedDaemonNativeEnrollmentPrepare;
///
/// let _ = VerifiedDaemonNativeEnrollmentPrepare { _private: () };
/// ```
pub struct VerifiedDaemonNativeEnrollmentPrepare {
    _private: (),
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) peer: Option<runne_macos_process_identity::MacOsLocalPeerProcessIdentity>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) peer_binding: [u8; 32],
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) paths: Option<NativeEnrollmentArtifactPathsV1>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) admission: Option<NativeEnrollmentTupleAdmission>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) profile_directory: Option<PathBuf>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) runtime_root: Option<PathBuf>,
}

impl VerifiedDaemonNativeEnrollmentPrepare {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) const fn peer_bound(
        peer: runne_macos_process_identity::MacOsLocalPeerProcessIdentity,
        peer_binding: [u8; 32],
        paths: NativeEnrollmentArtifactPathsV1,
        admission: NativeEnrollmentTupleAdmission,
        profile_directory: PathBuf,
        runtime_root: PathBuf,
    ) -> Self {
        Self {
            _private: (),
            peer: Some(peer),
            peer_binding,
            paths: Some(paths),
            admission: Some(admission),
            profile_directory: Some(profile_directory),
            runtime_root: Some(runtime_root),
        }
    }

    #[cfg(test)]
    const fn unbound_for_internal_test() -> Self {
        Self {
            _private: (),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            peer: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            peer_binding: [0; 32],
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            paths: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            admission: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            profile_directory: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            runtime_root: None,
        }
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[path = "daemon_installed/tests.rs"]
pub(super) mod tests;
