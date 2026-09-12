#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
use super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleError};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use runne_macos_process_identity::MacOsLocalPeerProcessIdentity;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use sha2::{Digest as _, Sha256};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::{
    fs::{File, OpenOptions},
    num::NonZeroU32,
    os::unix::{
        fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    str::FromStr as _,
};

const ACTIVATION_STATE_DIRECTORY: &str = ".desktop-protected-activation";
const STAGED_EXECUTABLE_DIRECTORY: &str = "executables-v1";

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl NativeEnrollmentArtifactPathsV1 {
    /// Locates a candidate package only from the kernel-authenticated desktop peer.
    pub(super) fn resolve_installed_from_authenticated_desktop_peer(
        stream: &UnixStream,
    ) -> Result<(Self, MacOsLocalPeerProcessIdentity), NativeEnrollmentTupleError> {
        let peer = MacOsLocalPeerProcessIdentity::capture(stream)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if peer.euid() != rustix::process::geteuid().as_raw() {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let executable = peer_executable_path(peer.pid())?;
        peer.revalidate_same_peer(stream)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let paths = Self::from_macos_package_executable(&executable, "runne-desktop", false)?;
        peer.revalidate_same_peer(stream)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        Ok((paths, peer))
    }

    /// Verifies this staged daemon against the retained installed package tuple.
    pub(super) fn confirm_current_staged_daemon(
        &self,
        runtime_root: &Path,
        expected_digest: [u8; 32],
        identity: &super::macos_identity::MacOsCodeIdentityV1,
    ) -> Result<(), NativeEnrollmentTupleError> {
        self.confirm_current_daemon(expected_digest)?;
        let stage_directory = staged_directory(runtime_root)?;
        let executable =
            std::env::current_exe().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let executable =
            std::fs::canonicalize(executable).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let expected_name = format!(
            "{}-{}.runned",
            hex::encode(expected_digest),
            self.daemon_byte_length()?
        );
        if executable.parent() != Some(stage_directory.as_path())
            || executable
                .file_name()
                .is_none_or(|name| name != std::ffi::OsStr::new(&expected_name))
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let pid =
            NonZeroU32::new(std::process::id()).ok_or(NativeEnrollmentTupleError::Rejected)?;
        let start = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let staged = RetainedStagedDaemon::open(&executable, expected_digest)?;
        let code =
            SecCode::for_self(Flags::NONE).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let requirement = SecRequirement::from_str(&identity.requirement())
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        code.check_validity(
            Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
            &requirement,
        )
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !runne_macos_process_identity::MacOsProcessExecutableIdentity::observe(pid, &executable)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?
            .matches_file(&staged.metadata)
            || !staged.matches_current()?
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        self.confirm_current_daemon(expected_digest)?;
        (start
            == runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
                .map_err(|_| NativeEnrollmentTupleError::Rejected)?
            && staged.matches_current()?)
        .then_some(())
        .ok_or(NativeEnrollmentTupleError::Rejected)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn peer_executable_path(pid: NonZeroU32) -> Result<PathBuf, NativeEnrollmentTupleError> {
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid.get().cast_signed());
    SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?
        .path(Flags::NONE)
        .ok()
        .and_then(|path| path.to_path())
        .and_then(|path| std::fs::canonicalize(path).ok())
        .ok_or(NativeEnrollmentTupleError::Rejected)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn staged_directory(runtime_root: &Path) -> Result<PathBuf, NativeEnrollmentTupleError> {
    let root =
        std::fs::canonicalize(runtime_root).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if root != runtime_root {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    private_directory(&root)?;
    let state = root.join(ACTIVATION_STATE_DIRECTORY);
    private_directory(&state)?;
    let stage = state.join(STAGED_EXECUTABLE_DIRECTORY);
    private_directory(&stage)?;
    std::fs::canonicalize(stage).map_err(|_| NativeEnrollmentTupleError::Rejected)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn private_directory(path: &Path) -> Result<(), NativeEnrollmentTupleError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    (metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o077 == 0)
        .then_some(())
        .ok_or(NativeEnrollmentTupleError::Rejected)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct RetainedStagedDaemon {
    file: File,
    metadata: std::fs::Metadata,
    path: PathBuf,
    digest: [u8; 32],
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl RetainedStagedDaemon {
    fn open(path: &Path, expected_digest: [u8; 32]) -> Result<Self, NativeEnrollmentTupleError> {
        let before =
            std::fs::symlink_metadata(path).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !before.file_type().is_file() || before.file_type().is_symlink() || before.nlink() != 1 {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let metadata = file
            .metadata()
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let after =
            std::fs::symlink_metadata(path).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if metadata.dev() != before.dev()
            || metadata.ino() != before.ino()
            || metadata.nlink() != 1
            || after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o500
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let digest = hash_open_file(&file)?;
        (digest == expected_digest)
            .then_some(Self {
                file,
                metadata,
                path: path.to_owned(),
                digest,
            })
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    fn matches_current(&self) -> Result<bool, NativeEnrollmentTupleError> {
        let current = std::fs::symlink_metadata(&self.path)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        Ok(current.file_type().is_file()
            && !current.file_type().is_symlink()
            && current.dev() == self.metadata.dev()
            && current.ino() == self.metadata.ino()
            && current.nlink() == 1
            && hash_open_file(&self.file)? == self.digest)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hash_open_file(file: &File) -> Result<[u8; 32], NativeEnrollmentTupleError> {
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read_at(&mut buffer, offset)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| NativeEnrollmentTupleError::Rejected)?)
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[path = "daemon_paths/tests.rs"]
mod tests;
