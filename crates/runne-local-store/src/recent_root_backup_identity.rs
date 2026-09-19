use super::{Path, StoreOpenError};

#[cfg(unix)]
#[derive(Clone, Copy)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
    links: u64,
}

#[cfg(windows)]
#[derive(Clone, Copy)]
pub struct FileIdentity {
    id: runne_windows_native_handle::RegularFileId,
    links: u32,
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Copy)]
pub struct FileIdentity;

#[cfg(unix)]
impl PartialEq for FileIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

#[cfg(unix)]
impl Eq for FileIdentity {}

#[cfg(windows)]
impl PartialEq for FileIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

#[cfg(windows)]
impl Eq for FileIdentity {}

#[cfg(not(any(unix, windows)))]
impl PartialEq for FileIdentity {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

#[cfg(not(any(unix, windows)))]
impl Eq for FileIdentity {}

#[cfg(unix)]
impl FileIdentity {
    pub const fn links(self) -> u64 {
        self.links
    }
}

#[cfg(windows)]
impl FileIdentity {
    pub const fn native_id(self) -> runne_windows_native_handle::RegularFileId {
        self.id
    }
}

#[cfg(windows)]
impl FileIdentity {
    pub const fn links(self) -> u64 {
        self.links as u64
    }
}

#[cfg(not(any(unix, windows)))]
impl FileIdentity {
    pub const fn links(self) -> u64 {
        0
    }
}

#[cfg(unix)]
pub fn file_identity(path: &Path) -> Result<FileIdentity, StoreOpenError> {
    use std::os::unix::fs::MetadataExt;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StoreOpenError::PreV5BackupConflict);
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
    })
}

#[cfg(windows)]
pub fn file_identity(path: &Path) -> Result<FileIdentity, StoreOpenError> {
    let snapshot =
        runne_windows_native_handle::inspect_regular_file(path).map_err(|error| match error {
            runne_windows_native_handle::NativeFileError::Rejected => {
                StoreOpenError::PreV5BackupConflict
            }
            _ => StoreOpenError::PreV5BackupRecoveryRequired,
        })?;
    Ok(FileIdentity {
        id: snapshot.id(),
        links: snapshot.link_count(),
    })
}

#[cfg(not(any(unix, windows)))]
pub fn file_identity(_: &Path) -> Result<FileIdentity, StoreOpenError> {
    Err(StoreOpenError::PreV5BackupRecoveryRequired)
}

#[cfg(unix)]
pub fn sync_parent_directory(path: &Path) -> Result<(), StoreOpenError> {
    let parent = path
        .parent()
        .ok_or(StoreOpenError::PreV5BackupRecoveryRequired)?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)
}

#[cfg(not(unix))]
pub fn sync_parent_directory(_: &Path) -> Result<(), StoreOpenError> {
    Ok(())
}
