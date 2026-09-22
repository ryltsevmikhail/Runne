//! Exact spawn plan surface (B3 seam), split from the pidfd spawn core so
//! each responsibility stays bounded. The plan pins: argv, the single
//! DBUS_SESSION_BUS_ADDRESS environment entry, stdin ← broker control
//! socket, stdout ← private writer startup (handshake) socket, stderr ←
//! null, and the defense-in-depth close snapshot.

use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};

use nix::fcntl::OFlag;
use nix::spawn::PosixSpawnFileActions;
use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

use super::SessionBusAddress;

/// The exact spawn surface, pinned by tests (B3 seam).
pub struct SpawnPlan {
    pub argv: Vec<CString>,
    pub environment: Vec<CString>,
    /// (source descriptor, child descriptor) duplications.
    pub duplications: Vec<(i32, i32)>,
    /// Parent descriptors explicitly closed in the child.
    pub closes: Vec<i32>,
}

#[cfg(test)]
pub(in crate::provider_credential_broker) fn build_plan_for_tests(
    spec: &VerifiedWriterLaunchSpec,
    address: &SessionBusAddress,
    channel_fd: i32,
    handshake_fd: i32,
    stderr_fd: i32,
) -> Result<SpawnPlan, BrokerHandoffError> {
    build_plan(spec, address, channel_fd, handshake_fd, stderr_fd, None)
}

pub(in crate::provider_credential_broker) fn build_plan(
    spec: &VerifiedWriterLaunchSpec,
    address: &SessionBusAddress,
    channel_fd: i32,
    handshake_fd: i32,
    stderr_fd: i32,
    secret_fd: Option<i32>,
) -> Result<SpawnPlan, BrokerHandoffError> {
    if [channel_fd, handshake_fd, stderr_fd]
        .into_iter()
        .chain(secret_fd)
        .any(|fd| fd <= 3)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let executable = CString::new(spec.executable().to_string_lossy().as_bytes())
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let mode = CString::new(spec.arguments()[0]).map_err(|_| BrokerHandoffError::Rejected)?;
    let mut plan = SpawnPlan {
        argv: vec![executable, mode],
        environment: vec![
            CString::new(format!("DBUS_SESSION_BUS_ADDRESS={}", address.as_str()))
                .map_err(|_| BrokerHandoffError::Rejected)?,
        ],
        duplications: vec![
            (channel_fd, libc::STDIN_FILENO),
            (handshake_fd, libc::STDOUT_FILENO),
            (stderr_fd, libc::STDERR_FILENO),
        ],
        closes: vec![channel_fd, handshake_fd, stderr_fd],
    };
    if let Some(secret_fd) = secret_fd {
        plan.duplications.push((secret_fd, 3));
        plan.closes.push(secret_fd);
    }
    Ok(plan)
}

pub(super) fn apply_plan(plan: &SpawnPlan) -> Result<PosixSpawnFileActions, BrokerHandoffError> {
    let mut actions = PosixSpawnFileActions::init().map_err(|_| BrokerHandoffError::Unavailable)?;
    for (source, target) in &plan.duplications {
        actions
            .add_dup2(*source, *target)
            .map_err(|_| BrokerHandoffError::Unavailable)?;
    }
    for fd in &plan.closes {
        actions
            .add_close(*fd)
            .map_err(|_| BrokerHandoffError::Unavailable)?;
    }
    Ok(actions)
}

/// Defense-in-depth close set from the spawn-time descriptor snapshot.
pub(super) fn close_inventory(
    actions: &mut PosixSpawnFileActions,
    duplicated_channel: &OwnedFd,
    retain_secret: bool,
) -> Result<(), BrokerHandoffError> {
    let keep: [i32; 3] = [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO];
    let inventory =
        std::fs::read_dir("/proc/self/fd").map_err(|_| BrokerHandoffError::Unavailable)?;
    let mut descriptors: Vec<i32> = inventory
        .flatten()
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
        .collect();
    descriptors.sort_unstable();
    descriptors.dedup();
    for fd in descriptors {
        if fd == duplicated_channel.as_fd().as_raw_fd()
            || keep.contains(&fd)
            || (retain_secret && fd == 3)
        {
            continue;
        }
        actions
            .add_close(fd)
            .map_err(|_| BrokerHandoffError::Unavailable)?;
    }
    Ok(())
}

pub(super) fn open_null(flags: OFlag) -> Result<OwnedFd, BrokerHandoffError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(flags.bits());
    }
    let file = options
        .open("/dev/null")
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    Ok(file.into())
}

pub(super) fn duplicate_above_reserved(
    descriptor: &impl AsFd,
) -> Result<OwnedFd, BrokerHandoffError> {
    rustix::io::fcntl_dupfd_cloexec(descriptor, 4).map_err(|_| BrokerHandoffError::Unavailable)
}
