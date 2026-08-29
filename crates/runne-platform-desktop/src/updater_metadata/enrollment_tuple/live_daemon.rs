use std::fmt;

#[cfg(target_os = "macos")]
use std::{
    fs::File,
    num::NonZeroU32,
    os::unix::fs::{FileExt as _, MetadataExt as _},
    path::Path,
    str::FromStr as _,
};

#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::{Flags, GuestAttributes, SecCode, SecRequirement};
use sha2::{Digest as _, Sha256};

use crate::ProtectedBundledRuntimeError;

use super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission, macos_identity};

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
            .filter(|desktop| admission.macos_writer_code_identity.as_ref() != Some(*desktop)
                && admission.macos_daemon_code_identity.as_ref() != Some(*desktop))
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

    pub(crate) fn matches_protected_daemon_digest(&self, digest: [u8; 32]) -> bool {
        self.admission
            .as_ref()
            .is_some_and(|admission| admission.daemon_sha256 == digest)
    }
}

impl ConfirmedInstalledNativeEnrollment {
    pub(crate) fn matches_admission(&self, admission: &NativeEnrollmentTupleAdmission) -> bool {
        self.admission == *admission
    }

    #[cfg(test)]
    pub(crate) const fn test_only_from_admission(admission: NativeEnrollmentTupleAdmission) -> Self {
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

#[cfg(target_os = "macos")]
fn verify_macos_daemon(
    pid: NonZeroU32,
    expected_digest: [u8; 32],
    identity: &macos_identity::MacOsCodeIdentityV1,
) -> Result<(), ProtectedBundledRuntimeError> {
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid.get().cast_signed());
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    let requirement = SecRequirement::from_str(&identity.requirement())
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    code.check_validity(Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS, &requirement)
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    let live_path = code
        .path(Flags::NONE)
        .ok()
        .and_then(|path| path.to_path())
        .and_then(|path| std::fs::canonicalize(path).ok())
        .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
    let live = RetainedLiveDaemon::open(&live_path, expected_digest)?;
    if !runne_macos_process_identity::MacOsProcessExecutableIdentity::observe(pid, &live_path)
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?
        .matches_file(&live.metadata)
        || !live.matches_current()? {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
struct RetainedLiveDaemon {
    file: File,
    metadata: std::fs::Metadata,
    path: std::path::PathBuf,
    digest: [u8; 32],
}

#[cfg(target_os = "macos")]
impl RetainedLiveDaemon {
    fn open(path: &Path, expected_digest: [u8; 32]) -> Result<Self, ProtectedBundledRuntimeError> {
        let before = std::fs::symlink_metadata(path)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if !before.file_type().is_file() || before.file_type().is_symlink() || before.nlink() != 1 {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let file = File::open(path).map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let metadata = file.metadata().map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let after = std::fs::symlink_metadata(path)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if metadata.dev() != before.dev() || metadata.ino() != before.ino()
            || metadata.nlink() != 1 || after.dev() != metadata.dev() || after.ino() != metadata.ino()
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let digest = hash_open_file(&file)?;
        (digest == expected_digest).then_some(Self {
            file,
            metadata,
            path: path.to_owned(),
            digest,
        }).ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)
    }

    fn matches_current(&self) -> Result<bool, ProtectedBundledRuntimeError> {
        let current = std::fs::symlink_metadata(&self.path)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        Ok(current.file_type().is_file() && !current.file_type().is_symlink()
            && current.dev() == self.metadata.dev() && current.ino() == self.metadata.ino()
            && current.nlink() == 1 && hash_open_file(&self.file)? == self.digest)
    }
}

#[cfg(target_os = "macos")]
fn hash_open_file(file: &File) -> Result<[u8; 32], ProtectedBundledRuntimeError> {
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = file.read_at(&mut chunk, offset).map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if read == 0 { return Ok(hasher.finalize().into()); }
        hasher.update(&chunk[..read]);
        offset = offset.checked_add(u64::try_from(read).map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?)
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
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
