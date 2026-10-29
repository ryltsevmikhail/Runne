//! Immutable executable copy prepared from a broker-held file descriptor.
#![allow(unsafe_code)]

use super::error::MacOsCommandError as CommandError;
use sha2::{Digest, Sha256};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;

/// Owner-private copy of the exact bytes that can be executed after approval.
/// macOS has no sealed memfd; the copy lives in a private directory and is
/// verified again by identity and digest before the caller may execute it.
pub struct SealedExecutableSnapshot {
    file: File,
    path: PathBuf,
    directory: PathBuf,
    digest: [u8; 32],
    object_id: [u8; 16],
}

impl SealedExecutableSnapshot {
    /// Copies a held regular executable into a private image.
    ///
    /// # Errors
    /// Returns invalid or unavailable before execution if source validation,
    /// bounded copying, durability, or identity checks fail.
    pub fn from_held_file(source: &File) -> Result<Self, CommandError> {
        let Ok(stat) = fstat(source) else {
            return Err(CommandError::Invalid);
        };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_mode & 0o111 == 0
            || stat.st_size <= 0
            || stat.st_size as u64 > MAX_EXECUTABLE_BYTES
        {
            return Err(CommandError::Invalid);
        }
        let (directory, path, mut image) = create_private_image()?;
        let digest = copy_bounded(source, &mut image).map_err(|_| CommandError::Unavailable)?;
        image
            .set_permissions(std::fs::Permissions::from_mode(0o500))
            .and_then(|()| image.sync_all())
            .map_err(|_| CommandError::Unavailable)?;
        sync_directory(&directory)?;
        let reopened = reopen_verified(&path, &digest)?;
        Ok(Self {
            file: reopened,
            path,
            directory,
            digest,
            object_id: random_bytes()?,
        })
    }

    /// Private image path retained for identity rebinding before release.
    ///
    /// This is deliberately not a launch token: it is not part of the public
    /// API, and a release step must re-open it with `O_NOFOLLOW`, compare the
    /// descriptor with the held one, and treat the result as a check rather
    /// than an atomic bind. Executing the held descriptor is stronger.
    #[must_use]
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Digest of the bytes copied from the held source.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Stable non-secret object identity for this snapshot.
    #[must_use]
    pub const fn object_id(&self) -> &[u8; 16] {
        &self.object_id
    }

    /// Retained descriptor for identity rechecks; not a spawn handle.
    #[must_use]
    pub(super) const fn file(&self) -> &File {
        &self.file
    }

    /// Identity of this sealed object and its immutable generation.
    ///
    /// A macOS snapshot is a one-shot private copy, so it is never rotated and
    /// always reports generation `1`. A second snapshot of the same bytes is a
    /// distinct object with its own identity.
    #[must_use]
    pub const fn permission_identity(&self) -> ([u8; 16], u64) {
        (self.object_id, 1)
    }

    /// Re-proves that the retained descriptor still holds exactly these bytes.
    ///
    /// This checks the descriptor, not the path that currently names it: a
    /// rename or a replacement at the old path does not change the held bytes.
    ///
    /// # Errors
    /// Returns unverified when the private image was replaced, resized or is no
    /// longer a single-link regular file, and unavailable when it cannot be
    /// inspected.
    pub fn validate_seals(&self) -> Result<(), CommandError> {
        let stat = fstat(&self.file).map_err(|_| CommandError::Unavailable)?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 {
            return Err(CommandError::Unverified);
        }
        let digest = crate::local_command_digest::file_digest(&self.file)
            .map_err(|_| CommandError::Unverified)?;
        if digest != self.digest {
            return Err(CommandError::Unverified);
        }
        Ok(())
    }

    /// Re-proves that the private image path still names the held object.
    ///
    /// A release step must call this immediately before opening the path and
    /// still prefer executing the held descriptor, because the path can be
    /// replaced after any check. The path is opened with `O_NOFOLLOW` and
    /// `O_NONBLOCK`: a symlink is refused, and a FIFO planted at the private
    /// path cannot stall the check before the regular-file test rejects it.
    ///
    /// # Errors
    /// Returns unverified when the path is gone, names another object, or the
    /// reopened bytes no longer match the retained digest.
    pub(super) fn verify_path_binding(&self) -> Result<(), CommandError> {
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.path())
            .map_err(|_| CommandError::Unverified)?;
        let held = fstat(&self.file).map_err(|_| CommandError::Unavailable)?;
        let candidate = fstat(&opened).map_err(|_| CommandError::Unavailable)?;
        if candidate.st_mode & libc::S_IFMT != libc::S_IFREG
            || candidate.st_nlink != 1
            || candidate.st_dev != held.st_dev
            || candidate.st_ino != held.st_ino
        {
            return Err(CommandError::Unverified);
        }
        let digest = crate::local_command_digest::file_digest(&opened)
            .map_err(|_| CommandError::Unverified)?;
        if digest != self.digest {
            return Err(CommandError::Unverified);
        }
        Ok(())
    }
}

impl std::fmt::Debug for SealedExecutableSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedExecutableSnapshot")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl Drop for SealedExecutableSnapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn create_private_image() -> Result<(PathBuf, PathBuf, File), CommandError> {
    for _ in 0..4 {
        let directory = std::env::temp_dir().join(format!(
            "runne-sealed-{}-{}",
            std::process::id(),
            hex(&random_bytes()?)
        ));
        let created = DirBuilder::new().mode(0o700).create(&directory);
        if created.is_err() {
            continue;
        }
        let path = directory.join("image");
        let image = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path);
        match image {
            Ok(image) => return Ok((directory, path, image)),
            Err(_) => {
                let _ = std::fs::remove_dir_all(&directory);
            }
        }
    }
    Err(CommandError::Unavailable)
}

fn copy_bounded(source: &File, destination: &mut File) -> std::io::Result<[u8; 32]> {
    let mut source = unsafe { File::from_raw_fd(libc::dup(source.as_raw_fd())) };
    source.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied.saturating_add(read as u64);
        if copied > MAX_EXECUTABLE_BYTES {
            return Err(std::io::Error::other("executable bound"));
        }
        hasher.update(&buffer[..read]);
        destination.write_all(&buffer[..read])?;
    }
    if copied == 0 {
        return Err(std::io::Error::other("empty executable"));
    }
    Ok(hasher.finalize().into())
}

fn fstat(file: &File) -> std::io::Result<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat)
}

fn reopen_verified(path: &Path, digest: &[u8; 32]) -> Result<File, CommandError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| CommandError::Unavailable)?;
    let stat = fstat(&file).map_err(|_| CommandError::Unverified)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 {
        return Err(CommandError::Unverified);
    }
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    let reader = &file;
    reader
        .take(MAX_EXECUTABLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CommandError::Unverified)?;
    if bytes.len() as u64 != stat.st_size as u64
        || Sha256::digest(&bytes).as_slice() != digest.as_slice()
    {
        return Err(CommandError::Unverified);
    }
    Ok(file)
}

fn sync_directory(directory: &Path) -> Result<(), CommandError> {
    let file = File::open(directory).map_err(|_| CommandError::Unavailable)?;
    if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
        return Err(CommandError::Unavailable);
    }
    Ok(())
}

fn random_bytes() -> Result<[u8; 16], CommandError> {
    let mut bytes = [0_u8; 16];
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(CommandError::Unavailable);
    }
    Ok(bytes)
}

fn hex(bytes: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
#[path = "sealed_tests.rs"]
mod tests;
