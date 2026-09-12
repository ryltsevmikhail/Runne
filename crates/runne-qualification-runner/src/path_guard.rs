use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{self, CWD, FileType, Mode, OFlags};
use rustix::io::Errno;

#[path = "path_guard/journal.rs"]
mod journal;

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

use crate::QualificationReplayLedgerError;

pub const PRODUCTION_ROOT: &str =
    "/private/var/db/gocode/sourcecraft-native-qualification/bootstrap-replay-v1";
pub const DATABASE_NAME: &str = "ledger.sqlite3";

pub struct GuardedRoot {
    pub fd: OwnedFd,
    pub path: PathBuf,
    uid: u32,
    identity: DirectoryIdentity,
    production: bool,
}

pub struct OpenedDatabase {
    pub fd: OwnedFd,
    pub created: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

pub fn production_root() -> Result<GuardedRoot, QualificationReplayLedgerError> {
    let root = open_directory(CWD, Path::new("/"))?;
    verify_system_directory(&root)?;
    let private = open_directory(&root, "private")?;
    verify_system_directory(&private)?;
    let var = open_directory(&private, "var")?;
    verify_system_directory(&var)?;
    let db = open_directory(&var, "db")?;
    verify_system_directory(&db)?;
    let gocode = create_private_directory(&db, "gocode", 0)?;
    let qualification = create_private_directory(&gocode, "sourcecraft-native-qualification", 0)?;
    let root = create_private_directory(&qualification, "bootstrap-replay-v1", 0)?;
    guarded_root(root, PathBuf::from(PRODUCTION_ROOT), 0, true)
}

#[cfg(test)]
pub fn test_root(path: &Path, uid: u32) -> Result<GuardedRoot, QualificationReplayLedgerError> {
    let fd = open_directory(CWD, path)?;
    verify_private_directory(&fd, uid)?;
    guarded_root(fd, path.to_path_buf(), uid, false)
}

impl GuardedRoot {
    pub fn open_database(&self) -> Result<OpenedDatabase, QualificationReplayLedgerError> {
        let flags = OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let (file, created) = match fs::openat(
            &self.fd,
            DATABASE_NAME,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(file) => {
                fs::fchmod(&file, Mode::from_raw_mode(0o600))
                    .map_err(|_| QualificationReplayLedgerError)?;
                (file, true)
            }
            Err(Errno::EXIST) => (
                fs::openat(&self.fd, DATABASE_NAME, flags, Mode::empty())
                    .map_err(|_| QualificationReplayLedgerError)?,
                false,
            ),
            Err(_) => return Err(QualificationReplayLedgerError),
        };
        verify_database(&file, self.uid)?;
        if created {
            sync(&file)?;
            sync(&self.fd)?;
        }
        Ok(OpenedDatabase { fd: file, created })
    }

    pub fn verify_database_path(&self) -> Result<(), QualificationReplayLedgerError> {
        self.verify_current()?;
        let file = fs::openat(
            &self.fd,
            DATABASE_NAME,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| QualificationReplayLedgerError)?;
        verify_database(&file, self.uid)
    }

    pub fn verify_current(&self) -> Result<(), QualificationReplayLedgerError> {
        verify_private_directory(&self.fd, self.uid)?;
        let current = if self.production {
            open_existing_production_root()?
        } else {
            let current = open_directory(CWD, &self.path)?;
            verify_private_directory(&current, self.uid)?;
            current
        };
        (directory_identity(&current)? == self.identity)
            .then_some(())
            .ok_or(QualificationReplayLedgerError)
    }

    pub fn verify_database_witness(
        &self,
        fd: impl rustix::fd::AsFd,
    ) -> Result<(), QualificationReplayLedgerError> {
        verify_database(fd, self.uid)
    }
}

fn open_directory(
    parent: impl rustix::fd::AsFd,
    name: impl rustix::path::Arg,
) -> Result<OwnedFd, QualificationReplayLedgerError> {
    fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| QualificationReplayLedgerError)
}

fn create_private_directory(
    parent: &OwnedFd,
    name: &str,
    uid: u32,
) -> Result<OwnedFd, QualificationReplayLedgerError> {
    match fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(Errno::EXIST) => sync(parent)?,
        Err(_) => return Err(QualificationReplayLedgerError),
    }
    let directory = open_directory(parent, name)?;
    verify_private_directory(&directory, uid)?;
    sync(&directory)?;
    Ok(directory)
}

fn guarded_root(
    fd: OwnedFd,
    path: PathBuf,
    uid: u32,
    production: bool,
) -> Result<GuardedRoot, QualificationReplayLedgerError> {
    Ok(GuardedRoot {
        identity: directory_identity(&fd)?,
        fd,
        path,
        uid,
        production,
    })
}

fn open_existing_production_root() -> Result<OwnedFd, QualificationReplayLedgerError> {
    let root = open_directory(CWD, Path::new("/"))?;
    verify_system_directory(&root)?;
    let private = open_directory(&root, "private")?;
    verify_system_directory(&private)?;
    let var = open_directory(&private, "var")?;
    verify_system_directory(&var)?;
    let db = open_directory(&var, "db")?;
    verify_system_directory(&db)?;
    let gocode = open_directory(&db, "gocode")?;
    verify_private_directory(&gocode, 0)?;
    let qualification = open_directory(&gocode, "sourcecraft-native-qualification")?;
    verify_private_directory(&qualification, 0)?;
    let root = open_directory(&qualification, "bootstrap-replay-v1")?;
    verify_private_directory(&root, 0)?;
    Ok(root)
}

fn directory_identity(fd: &OwnedFd) -> Result<DirectoryIdentity, QualificationReplayLedgerError> {
    let stat = fs::fstat(fd).map_err(|_| QualificationReplayLedgerError)?;
    (stat.st_dev != 0 && stat.st_ino != 0)
        .then_some(DirectoryIdentity {
            device: stat
                .st_dev
                .try_into()
                .map_err(|_| QualificationReplayLedgerError)?,
            inode: stat.st_ino,
        })
        .ok_or(QualificationReplayLedgerError)
}

fn sync(fd: impl rustix::fd::AsFd) -> Result<(), QualificationReplayLedgerError> {
    #[cfg(test)]
    if FAIL_NEXT_SYNC.with(|fail| fail.replace(false)) {
        return Err(QualificationReplayLedgerError);
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    return fs::fcntl_fullfsync(fd).map_err(|_| QualificationReplayLedgerError);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    fs::fsync(fd).map_err(|_| QualificationReplayLedgerError)
}

#[cfg(test)]
pub fn fail_next_sync() {
    FAIL_NEXT_SYNC.with(|fail| fail.set(true));
}

fn verify_system_directory(
    fd: impl rustix::fd::AsFd,
) -> Result<(), QualificationReplayLedgerError> {
    require_no_extended_acl(fd.as_fd())?;
    let stat = fs::fstat(fd).map_err(|_| QualificationReplayLedgerError)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(QualificationReplayLedgerError);
    }
    Ok(())
}

fn verify_private_directory(
    fd: impl rustix::fd::AsFd,
    uid: u32,
) -> Result<(), QualificationReplayLedgerError> {
    require_no_extended_acl(fd.as_fd())?;
    let stat = fs::fstat(fd).map_err(|_| QualificationReplayLedgerError)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(QualificationReplayLedgerError);
    }
    Ok(())
}

fn verify_database(
    fd: impl rustix::fd::AsFd,
    uid: u32,
) -> Result<(), QualificationReplayLedgerError> {
    require_no_extended_acl(fd.as_fd())?;
    let stat = fs::fstat(fd).map_err(|_| QualificationReplayLedgerError)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != uid
        || stat.st_mode & 0o777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(QualificationReplayLedgerError);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_no_extended_acl(
    fd: std::os::fd::BorrowedFd<'_>,
) -> Result<(), QualificationReplayLedgerError> {
    runne_macos_file_security::require_no_extended_acl(fd)
        .map_err(|_| QualificationReplayLedgerError)
}

#[cfg(not(target_os = "macos"))]
fn require_no_extended_acl(
    _: std::os::fd::BorrowedFd<'_>,
) -> Result<(), QualificationReplayLedgerError> {
    Ok(())
}
