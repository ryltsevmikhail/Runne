//! Linux writer spawn profile (P0, race-free): pidfd-retained child with an
//! exact spawn plan, an early close-on-exec sweep, and a strictly validated
//! non-secret session-bus address.
//!
//! Reviewer resolutions B1–B3: (B1) resolved writer-side — the child's own
//! first-party entry performs an early single-threaded sweep
//! (`runne-cli writer_fd_sweep`) closing every inherited descriptor above
//! stdio before any broker or secret processing (regression:
//! `writer_entry_selftest` with a real `runne __provider-credential-broker-v1`
//! child), and this parent adds the spawn-time `/proc/self/fd` close snapshot
//! as defense-in-depth only. (B2) the child is retained exclusively through a
//! pidfd opened immediately after spawn; kill uses `pidfd_send_signal`, reap
//! uses `waitid(P_PIDFD)`, and there is no raw-PID fallback. (B3) the spawn
//! surface is the exact [`SpawnPlan`] seam in `plan.rs` that tests pin
//! directly. The production address stays the strictly validated
//! `/run/user/<euid>/bus` derivation.
//!
//! Descriptor layout (B8 stage 4): stdin carries the broker CONTROL socket
//! (rendezvous writer end — existing framing), stdout carries the PRIVATE
//! writer STARTUP (handshake) socket the writer adopts safely via
//! `std::io::stdout()`, stderr stays null. The desktop↔daemon rendezvous
//! control is a separate channel and is never mixed with these.

use std::ffi::CString;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;

use nix::fcntl::OFlag;
use nix::spawn::{PosixSpawnAttr, PosixSpawnFlags, posix_spawn};
use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

use super::UnixRetainedWriterProcess;

#[path = "linux_spawn/pair.rs"]
mod pair;
#[path = "linux_spawn/plan.rs"]
mod plan;
pub use pair::spawn_linux_pair_writer_from_prepared_handoff;
pub(in crate::provider_credential_broker) use plan::SpawnPlan;
#[cfg(test)]
pub(in crate::provider_credential_broker) use plan::build_plan_for_tests;
use plan::{apply_plan, build_plan, close_inventory, duplicate_above_reserved, open_null};

/// Strictly validated session-bus address. Production uses only the
/// euid-derived canonical socket; tests may validate a private fixture
/// socket through the same strict checks (absolute path, socket type,
/// own-euid ownership).
pub struct SessionBusAddress(String);

impl SessionBusAddress {
    /// Production derivation: `/run/user/<euid>/bus`, validated before use.
    pub fn for_production() -> Result<Self, BrokerHandoffError> {
        let address = format!("unix:path=/run/user/{}/bus", effective_uid());
        let path = address
            .strip_prefix("unix:path=")
            .ok_or(BrokerHandoffError::Rejected)?;
        probe_path_socket(std::path::Path::new(path))?;
        Ok(Self(address))
    }

    #[cfg(test)]
    pub fn for_tests(socket_path: &std::path::Path) -> Result<Self, BrokerHandoffError> {
        probe_path_socket(socket_path)?;
        Ok(Self(format!("unix:path={}", socket_path.to_string_lossy())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// B2: proves pidfd support before any child exists.
pub fn pidfd_capability_probe() -> Result<(), BrokerHandoffError> {
    let pid = rustix::process::getpid();
    drop(
        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
            .map_err(|_| BrokerHandoffError::Unavailable)?,
    );
    Ok(())
}

/// Production Linux spawn entry: the retained writer holds the broker
/// control socket on stdin and the private startup handshake socket on
/// stdout. Ownership of both writer ends transfers here; the caller keeps
/// the daemon-side peers.
///
/// # Errors
///
/// Fails closed on any plan, spawn, or pidfd-acquisition failure; a failed
/// acquisition kills and reaps the exact child through the pidfd (never a
/// raw-PID kill).
pub fn spawn_linux_writer_with_sockets(
    spec: &VerifiedWriterLaunchSpec,
    control_end: UnixStream,
    handshake_end: UnixStream,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    let address = SessionBusAddress::for_production()?;
    spawn_with_pidfd_acquisition(spec, control_end, handshake_end, &address, open_child_pidfd)
}

fn open_child_pidfd(pid: i32) -> std::io::Result<OwnedFd> {
    let child_pid =
        rustix::process::Pid::from_raw(pid).ok_or_else(|| std::io::Error::other("invalid pid"))?;
    rustix::process::pidfd_open(child_pid, rustix::process::PidfdFlags::empty())
        .map_err(std::io::Error::from)
}

/// Fault-injectable spawn: `acquire_pidfd` failure must never leave a silent
/// live child — both writer-facing sockets are dropped (the child observes
/// EOF, exits, and is reparented by init if this parent dies) and the error
/// is returned as an explicit unresolved-child failure the caller must
/// surface.
pub(in crate::provider_credential_broker) fn spawn_with_pidfd_acquisition(
    spec: &VerifiedWriterLaunchSpec,
    control_end: UnixStream,
    handshake_end: UnixStream,
    address: &SessionBusAddress,
    acquire_pidfd: impl FnMut(i32) -> std::io::Result<OwnedFd>,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    spawn_with_secret(
        spec,
        control_end,
        handshake_end,
        address,
        None,
        acquire_pidfd,
    )
}

fn spawn_with_secret(
    spec: &VerifiedWriterLaunchSpec,
    control_end: UnixStream,
    handshake_end: UnixStream,
    address: &SessionBusAddress,
    secret_reader: Option<OwnedFd>,
    mut acquire_pidfd: impl FnMut(i32) -> std::io::Result<OwnedFd>,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    pidfd_capability_probe()?;
    let channel = duplicate_above_reserved(&control_end)?;
    let handshake = duplicate_above_reserved(&handshake_end)?;
    let stderr_null = duplicate_above_reserved(&open_null(OFlag::O_WRONLY)?)?;
    let mut reserved_fd = Some(open_null(OFlag::O_RDONLY)?);
    let mut child_marker: Option<i32> = None;
    let plan = build_plan(
        spec,
        address,
        channel.as_fd().as_raw_fd(),
        handshake.as_fd().as_raw_fd(),
        stderr_null.as_fd().as_raw_fd(),
        secret_reader.as_ref().map(|fd| fd.as_raw_fd()),
    )?;
    let mut actions = apply_plan(&plan)?;
    close_inventory(&mut actions, &channel, secret_reader.is_some())?;
    let mut attributes = PosixSpawnAttr::init().map_err(|_| BrokerHandoffError::Unavailable)?;
    attributes
        .set_flags(PosixSpawnFlags::empty())
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let spawned = posix_spawn(
        plan.argv[0].as_c_str(),
        &actions,
        &attributes,
        &plan.argv.iter().map(CString::as_c_str).collect::<Vec<_>>(),
        &plan
            .environment
            .iter()
            .map(CString::as_c_str)
            .collect::<Vec<_>>(),
    )
    .map_err(|_| BrokerHandoffError::Unavailable);
    drop((control_end, handshake_end, stderr_null, secret_reader));
    let spawned_pid = spawned?;
    let pid = spawned_pid.as_raw();
    child_marker = Some(pid);
    match acquire_pidfd(pid) {
        Ok(pidfd) => UnixRetainedWriterProcess::from_spawned(pid, pidfd),
        Err(first) => {
            // Bounded cleanup of the OWN unreaped child through the REAL
            // retained kernel handle; no raw-PID fallback, no silent success.
            drop(reserved_fd.take());
            match acquire_pidfd(pid) {
                Ok(pidfd) => {
                    if let Some(child) = rustix::process::Pid::from_raw(pid) {
                        let _ = rustix::process::pidfd_send_signal(
                            &pidfd,
                            rustix::process::Signal::KILL,
                        );
                        let _ = rustix::process::waitid(
                            rustix::process::WaitId::PidFd(pidfd.as_fd()),
                            rustix::process::WaitIdOptions::EXITED,
                        );
                    }
                    drop(child_marker.take());
                    Err(BrokerHandoffError::Rejected)
                }
                Err(second) => {
                    drop((first, second, pid, child_marker.take()));
                    Err(BrokerHandoffError::Rejected)
                }
            }
        }
    }
}

pub(super) fn probe_path_socket(path: &std::path::Path) -> Result<(), BrokerHandoffError> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    if !path.is_absolute() {
        return Err(BrokerHandoffError::Rejected);
    }
    let metadata = std::fs::metadata(path).map_err(|_| BrokerHandoffError::Unavailable)?;
    if !metadata.file_type().is_socket() || metadata.uid() != effective_uid() {
        return Err(BrokerHandoffError::Unavailable);
    }
    Ok(())
}

fn effective_uid() -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    // /proc/self ownership mirrors our effective uid; not a secret read.
    std::fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .unwrap_or(u32::MAX)
}

#[cfg(all(test, target_os = "linux"))]
pub(in crate::provider_credential_broker) fn spawn_with_pidfd_acquisition_for_tests(
    spec: &VerifiedWriterLaunchSpec,
    control_end: UnixStream,
    handshake_end: UnixStream,
    address: &SessionBusAddress,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    spawn_with_pidfd_acquisition(spec, control_end, handshake_end, address, open_child_pidfd)
}
