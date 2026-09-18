use super::{BootstrapOutcome, LENGTH, error};
use crate::bootstrap::{FileIdentity, InstallationAnchorDir};
use crate::error::DaemonError;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use std::fs::File;
use std::os::fd::OwnedFd;

pub(super) struct AnchorDir<'a> {
    retained: &'a InstallationAnchorDir,
}
impl<'a> AnchorDir<'a> {
    pub(super) fn from_bootstrap(outcome: &'a BootstrapOutcome) -> Result<Self, DaemonError> {
        outcome.installation_anchor_dir.verify_current()?;
        Ok(Self {
            retained: &outcome.installation_anchor_dir,
        })
    }
    pub(super) const fn fd(&self) -> &OwnedFd {
        self.retained.daemon_fd()
    }
    pub(super) fn create(&self, name: &str) -> Result<File, DaemonError> {
        fs::openat(
            self.fd(),
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map(File::from)
        .map_err(|_| error())
    }
    pub(super) fn open_file(&self, name: &str) -> Result<File, DaemonError> {
        fs::openat(
            self.fd(),
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| error())
    }
    pub(super) fn stat(&self, name: &str) -> Result<FileIdentity, DaemonError> {
        checked_stat(&fs::statat(self.fd(), name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| error())?)
    }
    pub(super) fn exists(&self, name: &str) -> bool {
        self.stat(name).is_ok()
    }
    pub(super) fn verify_current(&self) -> Result<(), DaemonError> {
        self.retained.verify_current()
    }
}

pub(super) fn checked_file(file: &File) -> Result<FileIdentity, DaemonError> {
    checked_stat(&fs::fstat(file).map_err(|_| error())?)
}
fn checked_stat(stat: &rustix::fs::Stat) -> Result<FileIdentity, DaemonError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size != LENGTH as i64
    {
        return Err(error());
    }
    Ok(FileIdentity {
        dev: {
            #[cfg(not(target_os = "linux"))]
            {
                stat.st_dev as u64
            }
            #[cfg(target_os = "linux")]
            {
                stat.st_dev
            }
        },
        ino: stat.st_ino,
    })
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Fault {
    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    None,
    Parent,
    Temp,
    Final,
    BeforeMarker,
}
// The fault-injection fixtures back the macOS anchor tests only; the Linux
// anchor path is exercised by the production enrollment lifecycle instead.
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
static FAULT: std::sync::Mutex<Fault> = std::sync::Mutex::new(Fault::None);
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn set_fault(fault: Fault) {
    *FAULT.lock().unwrap() = fault;
}
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_SERIAL.lock().unwrap()
}
#[cfg(not(test))]
pub(super) enum Fault {
    Parent,
    Temp,
    Final,
    BeforeMarker,
}
pub(super) fn hook(_point: Fault, _parent: &AnchorDir<'_>, _name: &str) -> Result<(), DaemonError> {
    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    if *FAULT.lock().unwrap() == _point {
        *FAULT.lock().unwrap() = Fault::None;
        return fault_action(_point, _parent, _name);
    }
    Ok(())
}
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn fault_action(point: Fault, parent: &AnchorDir<'_>, name: &str) -> Result<(), DaemonError> {
    match point {
        Fault::Parent => Err(error()),
        Fault::Temp => {
            move_and_replace(parent, name)?;
            Ok(())
        }
        Fault::Final => {
            fs::unlinkat(parent.fd(), name, AtFlags::empty()).map_err(|_| error())?;
            replace(parent, name)?;
            Ok(())
        }
        Fault::BeforeMarker => Err(error()),
        Fault::None => Ok(()),
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn move_and_replace(parent: &AnchorDir<'_>, name: &str) -> Result<(), DaemonError> {
    let moved = format!("{name}.moved");
    fs::renameat_with(
        parent.fd(),
        name,
        parent.fd(),
        moved,
        fs::RenameFlags::empty(),
    )
    .map_err(|_| error())?;
    replace(parent, name)
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn replace(parent: &AnchorDir<'_>, name: &str) -> Result<(), DaemonError> {
    use std::io::Write as _;
    let mut file = parent.create(name)?;
    file.write_all(&[0; LENGTH]).map_err(|_| error())
}
