//! Immutable executable bytes prepared from a broker-held file descriptor.
#![allow(unsafe_code)]

use super::LinuxCommandError;
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};

const MAX_EXECUTABLE_BYTES: i64 = 64 * 1024 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
const REQUIRED_SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

/// Sealed memfd copy of the exact bytes that can be executed after approval.
pub struct SealedExecutableSnapshot {
    file: File,
}

impl SealedExecutableSnapshot {
    /// Copies a held regular executable into a sealed memfd using bounded
    /// positional reads. Caller hashes this returned fd and later gives this
    /// same fd to the Linux command gate.
    ///
    /// # Errors
    /// Returns unavailable or invalid before execution if memfd sealing,
    /// source validation, bounded copying, or descriptor operations fail.
    pub fn from_held_file(source: &File) -> Result<Self, LinuxCommandError> {
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(source.as_raw_fd(), &mut stat) } != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_mode & 0o111 == 0
            || stat.st_size <= 0
            || stat.st_size > MAX_EXECUTABLE_BYTES
        {
            return Err(LinuxCommandError::Invalid);
        }
        let name = c"runne-approved-executable";
        let raw = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if raw < 0 {
            return Err(LinuxCommandError::Unavailable);
        }
        let mut file = unsafe { File::from_raw_fd(raw as i32) };
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } != 0 {
            return Err(LinuxCommandError::Unavailable);
        }
        copy_bounded(source, &file, stat.st_size)?;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_SEALS) } != 0 {
            return Err(LinuxCommandError::Unavailable);
        }
        let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        if seals < 0 || seals & REQUIRED_SEALS != REQUIRED_SEALS {
            return Err(LinuxCommandError::Unavailable);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LinuxCommandError::Unavailable)?;
        Ok(Self { file })
    }

    /// Returns the sealed executable descriptor used for approval hashing and exec.
    #[must_use]
    pub const fn file(&self) -> &File {
        &self.file
    }

    pub(super) fn validate_seals(&self) -> Result<(), LinuxCommandError> {
        let seals = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) };
        if seals < 0 || seals & REQUIRED_SEALS != REQUIRED_SEALS {
            return Err(LinuxCommandError::Unverified);
        }
        Ok(())
    }
}

fn copy_bounded(source: &File, target: &File, size: i64) -> Result<(), LinuxCommandError> {
    let mut buffer = [0u8; CHUNK_BYTES];
    let mut offset = 0i64;
    while offset < size {
        let remaining = usize::try_from(size - offset).map_err(|_| LinuxCommandError::Invalid)?;
        let requested = remaining.min(buffer.len());
        let count = loop {
            let result = unsafe {
                libc::pread(
                    source.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    requested,
                    offset,
                )
            };
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break result;
        };
        if count <= 0 {
            return Err(LinuxCommandError::Unverified);
        }
        write_all(target, &buffer[..count as usize])?;
        offset = offset
            .checked_add(count as i64)
            .ok_or(LinuxCommandError::Invalid)?;
    }
    Ok(())
}

fn write_all(target: &File, bytes: &[u8]) -> Result<(), LinuxCommandError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = unsafe {
            libc::write(
                target.as_raw_fd(),
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if count <= 0 {
            return Err(LinuxCommandError::Unavailable);
        }
        offset += count as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn snapshot_is_bounded_sealed_and_independent_of_later_source_mutation() {
        let path = std::env::temp_dir().join(format!(
            "runne-sealed-executable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut source = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let original = b"approved bytes";
        source.write_all(original).unwrap();
        unsafe { libc::fchmod(source.as_raw_fd(), 0o700) };
        let snapshot = SealedExecutableSnapshot::from_held_file(&source).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();
        source.write_all(b"changed bytes!").unwrap();
        let seals = unsafe { libc::fcntl(snapshot.file().as_raw_fd(), libc::F_GET_SEALS) };
        assert!(seals & REQUIRED_SEALS == REQUIRED_SEALS);
        let mut bytes = Vec::new();
        snapshot
            .file()
            .try_clone()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, original);
        assert!(unsafe { libc::ftruncate(snapshot.file().as_raw_fd(), 0) } < 0);
        std::fs::remove_file(path).unwrap();
    }
}
