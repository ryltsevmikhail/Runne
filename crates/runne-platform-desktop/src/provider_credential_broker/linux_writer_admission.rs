//! Linux writer admission (M5): binds one spawned writer process to its
//! pinned image digest and retained start identity before the daemon grants
//! any broker authority.
//!
//! Admission compares the opened `/proc/<pid>/exe` object with an opened
//! spec executable, hashes the live executable descriptor, and rechecks the
//! retained process start identity around that work. This is postspawn
//! evidence only; it does not prove same-object execution at spawn.
//! Ticket one-use/TTL/replay and kill ownership live in the existing daemon
//! admission registry and are not re-implemented here.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};
use sha2::{Digest as _, Sha256};

use super::unix::UnixRetainedWriterProcess;
use super::unix::process_start_identity::observed_start_identity;

/// One admitted Linux writer bound to its measured process facts.
pub struct VerifiedLinuxWriterAdmission {
    image_digest: [u8; 32],
    start_identity: [u8; 32],
    pid: libc::pid_t,
}

impl VerifiedLinuxWriterAdmission {
    #[must_use]
    pub const fn image_digest(&self) -> [u8; 32] {
        self.image_digest
    }

    #[must_use]
    pub const fn start_identity(&self) -> [u8; 32] {
        self.start_identity
    }

    #[must_use]
    pub const fn pid(&self) -> libc::pid_t {
        self.pid
    }
}

/// Admits one retained writer against its pinned launch spec.
///
/// # Errors
///
/// Returns a closed failure when the live process no longer matches the
/// pinned image, the start identity drifted, or any fact is unreadable.
pub fn admit_linux_writer(
    process: &UnixRetainedWriterProcess,
    spec: &VerifiedWriterLaunchSpec,
) -> Result<VerifiedLinuxWriterAdmission, BrokerHandoffError> {
    admit_linux_writer_with_confirmation_hook(process, spec, || {})
}

pub(super) fn admit_linux_writer_with_confirmation_hook(
    process: &UnixRetainedWriterProcess,
    spec: &VerifiedWriterLaunchSpec,
    before_confirmation: impl FnOnce(),
) -> Result<VerifiedLinuxWriterAdmission, BrokerHandoffError> {
    let artifact = spec.artifact();
    let executable = artifact.executable();
    let pinned_digest = artifact.image_digest();
    let pid = process.retained_pid();
    let before = observed_start_identity(pid.unsigned_abs())?;
    if before != process.retained_start_identity() {
        return Err(BrokerHandoffError::Rejected);
    }
    let proc_exe = open_proc_executable(pid)?;
    let pinned_exe = open_pinned_executable(executable)?;
    if !same_file_object(&proc_exe, &pinned_exe)? {
        return Err(BrokerHandoffError::Rejected);
    }
    let measured = file_digest(&proc_exe)?;
    if measured != pinned_digest {
        return Err(BrokerHandoffError::Rejected);
    }
    before_confirmation();
    let after = observed_start_identity(pid.unsigned_abs())?;
    if after != before || after != process.retained_start_identity() {
        return Err(BrokerHandoffError::Rejected);
    }
    process.ensure_running()?;
    // A process can exec a different image without changing its PID or
    // /proc start time. Reopen proc exe after hashing so the confirmation
    // describes the image still installed in the live process, not merely
    // the earlier image held by `proc_exe`.
    let confirmed_exe = open_proc_executable(pid)?;
    if !same_file_object(&confirmed_exe, &proc_exe)?
        || !same_file_object(&confirmed_exe, &pinned_exe)?
    {
        return Err(BrokerHandoffError::Rejected);
    }
    Ok(VerifiedLinuxWriterAdmission {
        image_digest: pinned_digest,
        start_identity: after,
        pid,
    })
}

/// Open proc's magic exe link, which resolves to the image object held by the
/// kernel for this process. Hashing this descriptor avoids a pathname lookup.
fn open_proc_executable(pid: libc::pid_t) -> Result<File, BrokerHandoffError> {
    let file = File::open(format!("/proc/{pid}/exe")).map_err(|_| BrokerHandoffError::Rejected)?;
    if !file
        .metadata()
        .map_err(|_| BrokerHandoffError::Rejected)?
        .is_file()
    {
        return Err(BrokerHandoffError::Rejected);
    }
    Ok(file)
}

/// Open the final executable component without following a symlink. Parent
/// components are resolved by the OS, while object comparison with proc exe
/// prevents a raced replacement from being accepted.
fn open_pinned_executable(path: &Path) -> Result<File, BrokerHandoffError> {
    if !path.is_absolute() {
        return Err(BrokerHandoffError::Rejected);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    if !file
        .metadata()
        .map_err(|_| BrokerHandoffError::Rejected)?
        .is_file()
    {
        return Err(BrokerHandoffError::Rejected);
    }
    Ok(file)
}

fn same_file_object(left: &File, right: &File) -> Result<bool, BrokerHandoffError> {
    let left = left.metadata().map_err(|_| BrokerHandoffError::Rejected)?;
    let right = right.metadata().map_err(|_| BrokerHandoffError::Rejected)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn file_digest(file: &File) -> Result<[u8; 32], BrokerHandoffError> {
    let mut bytes = Vec::new();
    let mut file = file.try_clone().map_err(|_| BrokerHandoffError::Rejected)?;
    file.read_to_end(&mut bytes)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    Ok(Sha256::digest(&bytes).into())
}
