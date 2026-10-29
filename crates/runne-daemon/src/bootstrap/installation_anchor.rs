use crate::error::DaemonError;
use rustix::fs::{self, AtFlags, CWD, FileType, Mode, OFlags};
use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

pub(crate) struct InstallationAnchorDir {
    daemon_fd: OwnedFd,
    runtime_fd: OwnedFd,
    runtime_path: PathBuf,
    daemon_name: OsString,
    db_name: OsString,
    daemon_identity: FileIdentity,
    runtime_identity: FileIdentity,
    db_identity: FileIdentity,
}

impl InstallationAnchorDir {
    pub(crate) fn retain(
        daemon_dir: &Path,
        db_path: &Path,
        replay_integrity_key_path: &Path,
    ) -> Result<Self, DaemonError> {
        if replay_integrity_key_path.parent() != Some(daemon_dir) {
            return Err(error());
        }
        let runtime_dir = daemon_dir.parent().ok_or_else(error)?;
        let runtime_path = runtime_dir.to_path_buf();
        let daemon_name = daemon_dir.file_name().ok_or_else(error)?.to_os_string();
        let db_name = db_path.file_name().ok_or_else(error)?.to_os_string();
        let runtime_fd = open_dir(CWD, &runtime_path)?;
        let runtime_identity = directory_identity(&runtime_fd)?;
        let daemon_fd = open_dir(&runtime_fd, &daemon_name)?;
        let daemon_identity = checked_directory(&daemon_fd)?;
        let direct_db = open_file(CWD, db_path)?;
        let db_identity = checked_database(&direct_db)?;
        let retained_db = open_file(&daemon_fd, &db_name)?;
        if checked_database(&retained_db)? != db_identity {
            return Err(error());
        }
        Ok(Self {
            daemon_fd,
            runtime_fd,
            runtime_path,
            daemon_name,
            db_name,
            daemon_identity,
            runtime_identity,
            db_identity,
        })
    }

    pub(crate) fn verify_current(&self) -> Result<(), DaemonError> {
        let current_runtime = open_dir(CWD, &self.runtime_path)?;
        if directory_identity(&current_runtime)? != self.runtime_identity
            || checked_directory(&self.daemon_fd)? != self.daemon_identity
            || checked_directory_stat(&self.runtime_fd, &self.daemon_name)? != self.daemon_identity
        {
            return Err(error());
        }
        let db = open_file(&self.daemon_fd, &self.db_name)?;
        if checked_database(&db)? != self.db_identity
            || checked_database_stat(&self.daemon_fd, &self.db_name)? != self.db_identity
        {
            return Err(error());
        }
        Ok(())
    }

    pub(crate) const fn daemon_fd(&self) -> &OwnedFd {
        &self.daemon_fd
    }
}

#[derive(Eq, PartialEq)]
pub(crate) struct FileIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

fn open_dir(
    dirfd: impl rustix::fd::AsFd,
    name: impl rustix::path::Arg,
) -> Result<OwnedFd, DaemonError> {
    fs::openat(
        dirfd,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| error())
}

fn open_file(
    dirfd: impl rustix::fd::AsFd,
    name: impl rustix::path::Arg,
) -> Result<OwnedFd, DaemonError> {
    // A regular read fd can drop process-wide SQLite POSIX locks on close.
    #[cfg(target_os = "linux")]
    let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    fs::openat(dirfd, name, flags, Mode::empty()).map_err(|_| error())
}

fn checked_directory(fd: &OwnedFd) -> Result<FileIdentity, DaemonError> {
    let stat = fs::fstat(fd).map_err(|_| error())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(error());
    }
    Ok(identity(&stat))
}

fn directory_identity(fd: &OwnedFd) -> Result<FileIdentity, DaemonError> {
    let stat = fs::fstat(fd).map_err(|_| error())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(error());
    }
    Ok(identity(&stat))
}

fn checked_directory_stat(dirfd: &OwnedFd, name: &OsString) -> Result<FileIdentity, DaemonError> {
    let stat = fs::statat(dirfd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| error())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(error());
    }
    Ok(identity(&stat))
}

fn checked_database(fd: &OwnedFd) -> Result<FileIdentity, DaemonError> {
    let stat = fs::fstat(fd).map_err(|_| error())?;
    checked_database_stat_value(&stat)
}

fn checked_database_stat(dirfd: &OwnedFd, name: &OsString) -> Result<FileIdentity, DaemonError> {
    let stat = fs::statat(dirfd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| error())?;
    checked_database_stat_value(&stat)
}

fn checked_database_stat_value(stat: &rustix::fs::Stat) -> Result<FileIdentity, DaemonError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(error());
    }
    Ok(identity(stat))
}

#[cfg(target_os = "linux")]
fn device_id(stat: &rustix::fs::Stat) -> u64 {
    stat.st_dev
}

#[cfg(not(target_os = "linux"))]
fn device_id(stat: &rustix::fs::Stat) -> u64 {
    stat.st_dev as u64
}

fn identity(stat: &rustix::fs::Stat) -> FileIdentity {
    FileIdentity {
        dev: device_id(stat),
        ino: stat.st_ino,
    }
}

fn error() -> DaemonError {
    DaemonError::Bootstrap("native enrollment installation anchor unavailable".into())
}
