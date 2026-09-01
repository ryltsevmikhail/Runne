use std::fs::{File, Metadata};
use std::num::NonZeroU32;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

use sha2::{Digest as _, Sha256};

use super::super::MacOsPackagedWriterObservationError;

const MAX_ROLE_BYTES: u64 = 64 * 1024 * 1024;
const HASH_CHUNK_BYTES: usize = 16 * 1024;

pub(super) struct RetainedArtifact {
    file: File,
    captured: ArtifactSnapshot,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ArtifactSnapshot {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) uid: u32,
    pub(super) mode: u32,
    pub(super) links: u64,
    pub(super) length: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

impl RetainedArtifact {
    pub(super) fn capture(
        file: File,
        root_device: u64,
        root_uid: u32,
        executable: bool,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        let captured = snapshot(&file)?;
        valid_file_shape(&captured, root_device, root_uid, executable)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        let digest = measure(&file, &captured)?;
        Ok(Self {
            file,
            captured,
            digest,
        })
    }

    pub(super) fn revalidate(&self) -> Result<(), MacOsPackagedWriterObservationError> {
        (snapshot(&self.file)? == self.captured
            && measure(&self.file, &self.captured)? == self.digest)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)
    }

    pub(super) fn matches(&self, other: &Self) -> bool {
        self.captured == other.captured && self.digest == other.digest
    }

    pub(super) fn distinct_from(&self, other: &Self) -> bool {
        let another_vnode = (self.captured.device, self.captured.inode)
            != (other.captured.device, other.captured.inode);
        let another_digest = self.digest != other.digest;
        another_vnode && another_digest
    }

    pub(super) const fn snapshot(&self) -> &ArtifactSnapshot {
        &self.captured
    }

    pub(super) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[cfg(test)]
    pub(super) const fn test_only_corrupt_digest(&mut self) {
        self.digest[0] ^= 0x80;
    }

    pub(super) fn observe_executable_mapping(
        &self,
        pid: NonZeroU32,
    ) -> Result<crate::ffi::ExecutableVnodeIdentity, MacOsPackagedWriterObservationError> {
        crate::ffi::observe_executable_vnode_matching_file(pid, &self.file)
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
    }
}

fn snapshot(file: &File) -> Result<ArtifactSnapshot, MacOsPackagedWriterObservationError> {
    file.metadata()
        .map(|metadata| ArtifactSnapshot::from_metadata(&metadata))
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
}

impl ArtifactSnapshot {
    pub(super) fn from_file_for_match(
        file: &File,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        snapshot(file)
    }

    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            length: metadata.len(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }

    #[cfg(test)]
    const fn synthetic(device: u64, uid: u32, mode: u32, links: u64, length: u64) -> Self {
        Self {
            device,
            inode: 1,
            uid,
            mode,
            links,
            length,
            changed_seconds: 1,
            changed_nanoseconds: 1,
            modified_seconds: 1,
            modified_nanoseconds: 1,
        }
    }
}

fn measure(
    file: &File,
    expected: &ArtifactSnapshot,
) -> Result<[u8; 32], MacOsPackagedWriterObservationError> {
    let before = snapshot(file)?;
    if before != *expected {
        return Err(MacOsPackagedWriterObservationError::Rejected);
    }
    let mut digest = Sha256::new();
    let mut chunk = [0_u8; HASH_CHUNK_BYTES];
    let mut offset = 0_u64;
    while offset < before.length {
        let remaining = before.length - offset;
        let limit = usize::try_from(remaining.min(HASH_CHUNK_BYTES as u64))
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        let read = file
            .read_at(&mut chunk[..limit], offset)
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        if read == 0 {
            return Err(MacOsPackagedWriterObservationError::Rejected);
        }
        digest.update(&chunk[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
    }
    if file
        .read_at(&mut chunk[..1], offset)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?
        != 0
        || snapshot(file)? != before
    {
        return Err(MacOsPackagedWriterObservationError::Rejected);
    }
    Ok(digest.finalize().into())
}

fn valid_file_shape(
    snapshot: &ArtifactSnapshot,
    root_device: u64,
    root_uid: u32,
    executable: bool,
) -> bool {
    snapshot.device == root_device
        && snapshot.uid == root_uid
        && snapshot.mode & u32::from(libc::S_IFMT) == u32::from(libc::S_IFREG)
        && snapshot.mode & 0o022 == 0
        && (!executable || snapshot.mode & 0o100 != 0)
        && snapshot.links == 1
        && (1..=MAX_ROLE_BYTES).contains(&snapshot.length)
}

#[cfg(test)]
pub(crate) fn test_only_valid_file_shape(
    root: (u64, u32),
    observed: (u64, u32, u32, u64, u64),
    executable: bool,
) -> bool {
    let (device, uid, mode, links, length) = observed;
    valid_file_shape(
        &ArtifactSnapshot::synthetic(device, uid, mode, links, length),
        root.0,
        root.1,
        executable,
    )
}
