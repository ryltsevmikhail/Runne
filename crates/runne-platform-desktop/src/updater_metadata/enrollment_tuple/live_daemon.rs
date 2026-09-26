#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
use std::fmt;
#[path = "live_daemon/retained_live_daemon.rs"]
mod retained_live_daemon;
#[path = "live_daemon/v3_confirmation.rs"]
mod v3_confirmation;
#[cfg(target_os = "macos")]
pub(super) use retained_live_daemon::verify_macos_daemon;

#[cfg(target_os = "macos")]
use std::{
    fs::File,
    num::NonZeroU32,
    os::unix::fs::{FileExt as _, MetadataExt as _},
    path::Path,
    str::FromStr as _,
};

#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
#[cfg(target_os = "macos")]
use sha2::{Digest as _, Sha256};

use crate::ProtectedBundledRuntimeError;

#[cfg(target_os = "macos")]
use super::macos_identity;
use super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission};

/// Opaque fixed-layout admission retained while the native confirmation is open.
///
/// This process-local value intentionally implements neither `Clone` nor serde.
pub struct PreparedInstalledNativeEnrollment {
    admission: Option<NativeEnrollmentTupleAdmission>,
    paths: Option<NativeEnrollmentArtifactPathsV1>,
}

/// Opaque evidence for one current protected daemon after prompt-time revalidation.
///
/// This process-local value intentionally implements neither `Clone` nor serde.
pub struct ConfirmedInstalledNativeEnrollment {
    pub(super) admission: NativeEnrollmentTupleAdmission,
    pub(super) evidence: ProtectedDaemonTupleEvidence,
    pub(super) paths: Option<NativeEnrollmentArtifactPathsV1>,
}

pub(super) struct ProtectedDaemonTupleEvidence {
    pub(super) release_tuple: [u8; 32],
    pub(super) launch_authority: [u8; 16],
    pub(super) desktop_host: [u8; 16],
    pub(super) session: [u8; 16],
    pub(super) daemon: [u8; 16],
    pub(super) generation: u64,
    pub(super) process_start: [u8; 32],
}

pub struct NativeEnrollmentConfirmationV1 {
    pub process_start_before: [u8; 32],
    pub process_start_after: [u8; 32],
    pub launch_authority: [u8; 16],
    pub desktop_host: [u8; 16],
    pub session: [u8; 16],
    pub daemon: [u8; 16],
    pub generation: u64,
}

impl NativeEnrollmentTupleAdmission {
    pub(crate) const fn retain_installed_paths(
        self,
        paths: NativeEnrollmentArtifactPathsV1,
    ) -> PreparedInstalledNativeEnrollment {
        PreparedInstalledNativeEnrollment {
            admission: Some(self),
            paths: Some(paths),
        }
    }
}

impl PreparedInstalledNativeEnrollment {
    #[cfg(test)]
    pub(crate) const fn test_only_for_state_rejection() -> Self {
        Self {
            admission: None,
            paths: None,
        }
    }

    pub(crate) fn refresh_from(self, fresh: Self) -> Option<Self> {
        let old_admission = self.admission.as_ref()?;
        let old_paths = self.paths.as_ref()?;
        let fresh_admission = fresh.admission.as_ref()?;
        let fresh_paths = fresh.paths.as_ref()?;
        (old_admission == fresh_admission && old_paths.matches_retained(fresh_paths).ok()?)
            .then_some(fresh)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn confirm_current_daemon(
        &self,
        pid: NonZeroU32,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let admission = self
            .admission
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let paths = self
            .paths
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let desktop = admission
            .macos_desktop_code_identity
            .as_ref()
            .filter(|desktop| {
                admission.macos_writer_code_identity.as_ref() != Some(*desktop)
                    && admission.macos_daemon_code_identity.as_ref() != Some(*desktop)
            })
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let daemon = admission
            .macos_daemon_code_identity
            .as_ref()
            .filter(|identity| admission.macos_writer_code_identity.as_ref() != Some(*identity))
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        paths
            .confirm_current_macos_desktop(admission.desktop_sha256, desktop)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        paths
            .confirm_current_daemon(admission.daemon_sha256)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        verify_macos_daemon(pid, admission.daemon_sha256, daemon)?;
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    #[allow(clippy::unused_self, clippy::missing_const_for_fn)]
    pub(crate) fn confirm_current_daemon(
        &self,
        _pid: std::num::NonZeroU32,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
    }

    pub(crate) fn confirm(
        self,
        confirmation: &NativeEnrollmentConfirmationV1,
    ) -> Result<ConfirmedInstalledNativeEnrollment, ProtectedBundledRuntimeError> {
        if confirmation.process_start_before == [0; 32]
            || confirmation.process_start_before != confirmation.process_start_after
            || confirmation.session == [0; 16]
            || confirmation.daemon == [0; 16]
            || confirmation.generation == 0
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let admission = self
            .admission
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let paths = self
            .paths
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        Ok(ConfirmedInstalledNativeEnrollment {
            evidence: ProtectedDaemonTupleEvidence {
                release_tuple: admission.release_tuple_sha256,
                launch_authority: confirmation.launch_authority,
                desktop_host: confirmation.desktop_host,
                session: confirmation.session,
                daemon: confirmation.daemon,
                generation: confirmation.generation,
                process_start: confirmation.process_start_after,
            },
            admission,
            paths: Some(paths),
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn confirm_linux(
        self,
        launch_authority: [u8; 16],
        desktop_host: [u8; 16],
        session: [u8; 16],
        daemon: [u8; 16],
        generation: u64,
        process_start: [u8; 32],
    ) -> Result<ConfirmedInstalledNativeEnrollment, ProtectedBundledRuntimeError> {
        if launch_authority == [0; 16]
            || desktop_host == [0; 16]
            || session == [0; 16]
            || daemon == [0; 16]
            || generation == 0
            || process_start == [0; 32]
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let admission = self.admission.ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let paths = self.paths.ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        Ok(ConfirmedInstalledNativeEnrollment {
            evidence: ProtectedDaemonTupleEvidence {
                release_tuple: admission.release_tuple_sha256,
                launch_authority,
                desktop_host,
                session,
                daemon,
                generation,
                process_start,
            },
            admission,
            paths: Some(paths),
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn confirm_linux_daemon_image(
        &self,
        pid: u32,
        start_ticks: u64,
        launched_file: &std::fs::File,
        runtime_root: &std::path::Path,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let admission = self.admission.as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let paths = self.paths.as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        paths.confirm_daemon_process(
            pid, start_ticks, launched_file, runtime_root, admission.daemon_sha256,
        )
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let measured = paths.daemon_file.measure()
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        (hex::decode(measured).ok().as_deref() == Some(&admission.daemon_sha256))
            .then_some(())
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)
    }

    pub(crate) fn matches_protected_daemon_digest(&self, digest: [u8; 32]) -> bool {
        self.admission
            .as_ref()
            .is_some_and(|admission| admission.daemon_sha256 == digest)
    }
}

impl ConfirmedInstalledNativeEnrollment {
    pub(crate) const fn installed_generation(&self) -> u64 {
        self.admission.installed_generation
    }

    pub(crate) fn matches_admission(&self, admission: &NativeEnrollmentTupleAdmission) -> bool {
        self.admission == *admission
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) const fn test_only_from_admission(
        admission: NativeEnrollmentTupleAdmission,
    ) -> Self {
        Self {
            evidence: ProtectedDaemonTupleEvidence {
                release_tuple: admission.release_tuple_sha256,
                launch_authority: [1; 16],
                desktop_host: [5; 16],
                session: [2; 16],
                daemon: [3; 16],
                generation: 1,
                process_start: [4; 32],
            },
            admission,
            paths: None,
        }
    }
}

impl fmt::Debug for PreparedInstalledNativeEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedInstalledNativeEnrollment(<retained-fixed-layout>)")
    }
}

impl fmt::Debug for ConfirmedInstalledNativeEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmedInstalledNativeEnrollment(<current-daemon>)")
    }
}
