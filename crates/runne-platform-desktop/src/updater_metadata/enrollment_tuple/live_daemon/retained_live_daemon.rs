#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
#[cfg(target_os = "macos")]
use sha2::{Digest as _, Sha256};
#[cfg(target_os = "macos")]
use std::{
    fs::File,
    num::NonZeroU32,
    os::unix::fs::{FileExt as _, MetadataExt as _},
    path::Path,
    str::FromStr as _,
};

#[cfg(target_os = "macos")]
use super::super::macos_identity;
#[cfg(target_os = "macos")]
use crate::ProtectedBundledRuntimeError;

#[cfg(target_os = "macos")]
pub(super) fn verify_macos_daemon(
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
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
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
        || !live.matches_current()?
    {
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
        let metadata = file
            .metadata()
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let after = std::fs::symlink_metadata(path)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if metadata.dev() != before.dev()
            || metadata.ino() != before.ino()
            || metadata.nlink() != 1
            || after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let digest = hash_open_file(&file)?;
        (digest == expected_digest)
            .then_some(Self {
                file,
                metadata,
                path: path.to_owned(),
                digest,
            })
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)
    }

    fn matches_current(&self) -> Result<bool, ProtectedBundledRuntimeError> {
        let current = std::fs::symlink_metadata(&self.path)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        Ok(current.file_type().is_file()
            && !current.file_type().is_symlink()
            && current.dev() == self.metadata.dev()
            && current.ino() == self.metadata.ino()
            && current.nlink() == 1
            && hash_open_file(&self.file)? == self.digest)
    }
}

#[cfg(target_os = "macos")]
fn hash_open_file(file: &File) -> Result<[u8; 32], ProtectedBundledRuntimeError> {
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read_at(&mut chunk, offset)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&chunk[..read]);
        offset = offset
            .checked_add(
                u64::try_from(read).map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?,
            )
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
    }
}
