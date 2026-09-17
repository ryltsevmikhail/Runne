use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

use runne_macos_file_security::require_no_extended_acl;
use rustix::fs::{self, CWD, FileType, Mode, OFlags};
use sha2::Digest as _;

use crate::{
    PRODUCTION_BOOTSTRAP_POLICY_PATH, QualificationBootstrapPolicyError,
    RetainedQualificationBootstrapPolicy, decode,
};

pub struct RetainedPath {
    path: String,
    uid: u32,
    #[cfg(test)]
    fixture: bool,
    directories: Vec<DirectoryIdentity>,
    file: File,
    file_identity: Identity,
    digest: [u8; 32],
    bytes: Vec<u8>,
}
impl RetainedPath {
    pub fn revalidate(&self) -> Result<(), QualificationBootstrapPolicyError> {
        if identity(&self.file)? != self.file_identity {
            return Err(QualificationBootstrapPolicyError::Rejected);
        }
        #[cfg(test)]
        let current = if self.fixture {
            read_fixture_path(&self.path, self.uid)?
        } else {
            read_path(&self.path, self.uid)?
        };
        #[cfg(not(test))]
        let current = read_path(&self.path, self.uid)?;
        (current.directories == self.directories
            && current.file_identity == self.file_identity
            && current.digest == self.digest
            && current.bytes == self.bytes)
            .then_some(())
            .ok_or(QualificationBootstrapPolicyError::Rejected)
    }
}
struct LoadedPath {
    directories: Vec<DirectoryIdentity>,
    file: File,
    file_identity: Identity,
    digest: [u8; 32],
    bytes: Vec<u8>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u16,
    nlink: u64,
    size: u64,
    ctime: i64,
    ctime_nsec: u32,
    mtime: i64,
    mtime_nsec: u32,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u16,
}

pub fn load_production()
-> Result<RetainedQualificationBootstrapPolicy, QualificationBootstrapPolicyError> {
    load_path(PRODUCTION_BOOTSTRAP_POLICY_PATH, 0)
}
#[cfg(test)]
pub fn load_fixture(
    path: &Path,
    uid: u32,
) -> Result<RetainedQualificationBootstrapPolicy, QualificationBootstrapPolicyError> {
    load_path_fixture(
        path.to_str()
            .ok_or(QualificationBootstrapPolicyError::Rejected)?,
        uid,
    )
}
fn load_path(
    path: &str,
    uid: u32,
) -> Result<RetainedQualificationBootstrapPolicy, QualificationBootstrapPolicyError> {
    let retained = read_path(path, uid)?;
    let policy = decode(&retained.bytes)?;
    Ok(RetainedQualificationBootstrapPolicy {
        policy,
        retained: RetainedPath {
            path: path.into(),
            uid,
            #[cfg(test)]
            fixture: false,
            directories: retained.directories,
            file: retained.file,
            file_identity: retained.file_identity,
            digest: retained.digest,
            bytes: retained.bytes,
        },
    })
}
#[cfg(test)]
fn load_path_fixture(
    path: &str,
    uid: u32,
) -> Result<RetainedQualificationBootstrapPolicy, QualificationBootstrapPolicyError> {
    let retained = read_fixture_path(path, uid)?;
    let policy = decode(&retained.bytes)?;
    Ok(RetainedQualificationBootstrapPolicy {
        policy,
        retained: RetainedPath {
            path: path.into(),
            uid,
            #[cfg(test)]
            fixture: true,
            directories: retained.directories,
            file: retained.file,
            file_identity: retained.file_identity,
            digest: retained.digest,
            bytes: retained.bytes,
        },
    })
}
fn read_path(path: &str, uid: u32) -> Result<LoadedPath, QualificationBootstrapPolicyError> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(QualificationBootstrapPolicyError::Rejected);
    }
    let mut parts = path.components();
    if !matches!(parts.next(), Some(Component::RootDir)) {
        return Err(QualificationBootstrapPolicyError::Rejected);
    }
    let names: Vec<_> = parts
        .map(|part| match part {
            Component::Normal(name) => Ok(name),
            _ => Err(QualificationBootstrapPolicyError::Rejected),
        })
        .collect::<Result<_, _>>()?;
    let (file_name, parents) = names
        .split_last()
        .ok_or(QualificationBootstrapPolicyError::Rejected)?;
    let mut directory = open_root()?;
    let mut directories = vec![checked_directory(&directory, uid)?];
    for name in parents {
        directory = open_directory(&directory, name)?;
        directories.push(checked_directory(&directory, uid)?);
    }
    read_file(&directory, file_name, directories, uid)
}
#[cfg(test)]
fn read_fixture_path(
    path: &str,
    uid: u32,
) -> Result<LoadedPath, QualificationBootstrapPolicyError> {
    let path = Path::new(path);
    let parent = path
        .parent()
        .ok_or(QualificationBootstrapPolicyError::Rejected)?;
    let name = path
        .file_name()
        .ok_or(QualificationBootstrapPolicyError::Rejected)?;
    let directory = fs::openat(
        CWD,
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| QualificationBootstrapPolicyError::Rejected)?;
    let directories = vec![checked_directory(&directory, uid)?];
    read_file(&directory, name, directories, uid)
}
fn read_file(
    directory: &OwnedFd,
    file_name: &std::ffi::OsStr,
    directories: Vec<DirectoryIdentity>,
    uid: u32,
) -> Result<LoadedPath, QualificationBootstrapPolicyError> {
    let fd = fs::openat(
        directory,
        file_name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| QualificationBootstrapPolicyError::Rejected)?;
    let file = File::from(fd);
    let file_identity = checked_file(&file, uid)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(file_identity.size)
            .map_err(|_| QualificationBootstrapPolicyError::Rejected)?,
    );
    (&file)
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| QualificationBootstrapPolicyError::Rejected)?;
    if bytes.is_empty() || bytes.len() > 65_536 || identity(&file)? != file_identity {
        return Err(QualificationBootstrapPolicyError::Rejected);
    }
    Ok(LoadedPath {
        directories,
        file,
        file_identity,
        digest: sha2::Sha256::digest(&bytes).into(),
        bytes,
    })
}
fn open_root() -> Result<OwnedFd, QualificationBootstrapPolicyError> {
    fs::openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| QualificationBootstrapPolicyError::Rejected)
}
fn open_directory(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
) -> Result<OwnedFd, QualificationBootstrapPolicyError> {
    fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| QualificationBootstrapPolicyError::Rejected)
}
fn checked_directory(
    fd: &OwnedFd,
    uid: u32,
) -> Result<DirectoryIdentity, QualificationBootstrapPolicyError> {
    let value = identity(fd)?;
    (FileType::from_raw_mode(value.mode).is_dir()
        && (value.uid == 0 || value.uid == uid)
        && value.mode & 0o022 == 0)
        .then_some(DirectoryIdentity {
            device: value.device,
            inode: value.inode,
            uid: value.uid,
            mode: value.mode,
        })
        .ok_or(QualificationBootstrapPolicyError::Rejected)
}
fn checked_file(fd: &File, uid: u32) -> Result<Identity, QualificationBootstrapPolicyError> {
    let value = identity(fd)?;
    (FileType::from_raw_mode(value.mode).is_file()
        && value.uid == uid
        && value.nlink == 1
        && value.mode & 0o022 == 0
        && value.size > 0
        && value.size <= 65_536)
        .then_some(value)
        .ok_or(QualificationBootstrapPolicyError::Rejected)
}
fn identity(fd: impl rustix::fd::AsFd) -> Result<Identity, QualificationBootstrapPolicyError> {
    require_no_extended_acl(fd.as_fd()).map_err(|_| QualificationBootstrapPolicyError::Rejected)?;
    let stat = fs::fstat(fd).map_err(|_| QualificationBootstrapPolicyError::Rejected)?;
    Ok(Identity {
        device: stat
            .st_dev
            .try_into()
            .map_err(|_| QualificationBootstrapPolicyError::Rejected)?,
        inode: stat.st_ino,
        uid: stat.st_uid,
        mode: stat.st_mode,
        nlink: u64::from(stat.st_nlink),
        size: stat
            .st_size
            .try_into()
            .map_err(|_| QualificationBootstrapPolicyError::Rejected)?,
        ctime: stat.st_ctime,
        ctime_nsec: stat
            .st_ctime_nsec
            .try_into()
            .map_err(|_| QualificationBootstrapPolicyError::Rejected)?,
        mtime: stat.st_mtime,
        mtime_nsec: stat
            .st_mtime_nsec
            .try_into()
            .map_err(|_| QualificationBootstrapPolicyError::Rejected)?,
    })
}
