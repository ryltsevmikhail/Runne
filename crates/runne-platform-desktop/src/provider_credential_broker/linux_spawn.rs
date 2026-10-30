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
//! surface is the exact `SpawnPlan` seam in `plan.rs` that tests pin
//! directly. The production address stays the strictly validated
//! `/run/user/<euid>/bus` derivation.
//!
//! Descriptor layout (B8 stage 4): stdin carries the broker CONTROL socket
//! (rendezvous writer end — existing framing), stdout carries the PRIVATE
//! writer STARTUP (handshake) socket the writer adopts safely via
//! `std::io::stdout()`, stderr stays null. The desktop↔daemon rendezvous
//! control is a separate channel and is never mixed with these.

use std::ffi::CString;
use std::os::fd::{AsFd as _, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use nix::fcntl::OFlag;
use nix::spawn::{PosixSpawnAttr, PosixSpawnFlags, posix_spawn};
use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

use super::UnixRetainedWriterProcess;

#[cfg(target_os = "linux")]
#[path = "linux_spawn/control_only.rs"]
mod control_only;
#[path = "linux_spawn/pair.rs"]
mod pair;
#[path = "linux_spawn/plan.rs"]
mod plan;
#[path = "linux_spawn/provenance.rs"]
mod provenance;
#[cfg(all(
    test,
    feature = "linux-native-enrollment-qualification",
    not(feature = "test-support")
))]
#[path = "linux_spawn/qualification_env_tests.rs"]
mod qualification_env_tests;
#[path = "linux_spawn/session_bus.rs"]
mod session_bus;
#[cfg(all(test, target_os = "linux"))]
#[path = "linux_spawn/test_entries.rs"]
mod test_entries;
#[cfg(target_os = "linux")]
pub use control_only::spawn_linux_writer_from_prepared_handoff;
pub use pair::spawn_linux_pair_writer_from_prepared_handoff;
#[cfg(test)]
pub(in crate::provider_credential_broker) use plan::SpawnPlan;
#[cfg(test)]
pub(in crate::provider_credential_broker) use plan::build_plan_for_tests;
use plan::{apply_plan, build_plan, close_inventory, duplicate_above_reserved, open_null};
#[cfg(not(test))]
use provenance::SpawnOperation;
#[cfg(test)]
pub(in crate::provider_credential_broker) use provenance::SpawnOperation;
#[cfg(all(test, target_os = "linux"))]
pub(in crate::provider_credential_broker) use provenance::TestSpawnFailure;
use provenance::{SpawnDiagnostic, injected};
pub use session_bus::SessionBusAddress;
#[cfg(all(test, target_os = "linux"))]
pub(in crate::provider_credential_broker) use test_entries::spawn_with_injected_fault_for_tests;
#[cfg(all(test, target_os = "linux"))]
pub(in crate::provider_credential_broker) use test_entries::spawn_with_pidfd_acquisition_for_tests;

#[cfg(any(
    feature = "test-support",
    feature = "linux-native-enrollment-qualification"
))]
fn opted_in_fixture_root() -> Result<Option<std::path::PathBuf>, BrokerHandoffError> {
    plan::opted_in_fixture_root()
}

#[cfg(not(any(
    feature = "test-support",
    feature = "linux-native-enrollment-qualification"
)))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "qualified fixture implementation of this API is fallible"
)]
const fn opted_in_fixture_root() -> Result<Option<std::path::PathBuf>, BrokerHandoffError> {
    Ok(None)
}

/// B2: proves pidfd support before any child exists.
pub fn pidfd_capability_probe() -> Result<(), BrokerHandoffError> {
    pidfd_capability_probe_faulted(&|_| None).map_err(SpawnDiagnostic::into_public)
}

fn pidfd_capability_probe_faulted(
    fault: &impl Fn(SpawnOperation) -> Option<i32>,
) -> Result<(), SpawnDiagnostic> {
    if let Some(failure) = injected(fault, SpawnOperation::PidfdCapabilityProbe) {
        return Err(failure);
    }
    let pid = rustix::process::getpid();
    rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
        .map(drop)
        .map_err(|error| SpawnDiagnostic::unavailable(SpawnOperation::PidfdCapabilityProbe, &error))
}

/// Production Linux spawn entry for the exact retained writer child.
///
/// The retained writer holds the broker control socket on stdin and the
/// private startup handshake socket on stdout. Ownership of both writer ends
/// transfers here; the caller keeps the daemon-side peers.
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
    acquire_pidfd: impl FnMut(i32) -> std::io::Result<OwnedFd>,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    spawn_with_secret_faulted(
        spec,
        control_end,
        handshake_end,
        address,
        secret_reader,
        acquire_pidfd,
        &|_| None,
    )
    .map_err(SpawnDiagnostic::into_public)
}

/// Parent-side spawn sequence with per-operation provenance: every
/// `Unavailable` mapping records its exact stage plus the raw OS errno the
/// failing error itself carried. The `fault` injector is production-neutral
/// (`&|_| None`) and exists only so tests can prove each mapping; every
/// injected stage preempts its operation, so no synthetic fault spawns a
/// child or touches real host resources.
fn spawn_with_secret_faulted(
    spec: &VerifiedWriterLaunchSpec,
    control_end: UnixStream,
    handshake_end: UnixStream,
    address: &SessionBusAddress,
    secret_reader: Option<OwnedFd>,
    mut acquire_pidfd: impl FnMut(i32) -> std::io::Result<OwnedFd>,
    fault: &impl Fn(SpawnOperation) -> Option<i32>,
) -> Result<UnixRetainedWriterProcess, SpawnDiagnostic> {
    pidfd_capability_probe_faulted(fault)?;
    let channel = duplicate_above_reserved(&control_end, SpawnOperation::DuplicateControl, fault)?;
    let handshake =
        duplicate_above_reserved(&handshake_end, SpawnOperation::DuplicateHandshake, fault)?;
    let stderr_null = duplicate_above_reserved(
        &open_null(OFlag::O_WRONLY, SpawnOperation::OpenNullWritable, fault)?,
        SpawnOperation::DuplicateNullWritable,
        fault,
    )?;
    let mut reserved_fd = Some(open_null(
        OFlag::O_RDONLY,
        SpawnOperation::OpenNullReadable,
        fault,
    )?);
    let fixture_root = opted_in_fixture_root()?;
    let plan = build_plan(
        spec,
        address,
        channel.as_fd().as_raw_fd(),
        handshake.as_fd().as_raw_fd(),
        stderr_null.as_fd().as_raw_fd(),
        secret_reader.as_ref().map(AsRawFd::as_raw_fd),
        fixture_root.as_deref(),
    )?;
    let mut actions = apply_plan(&plan, fault)?;
    close_inventory(&mut actions, &channel, secret_reader.is_some(), fault)?;
    if let Some(failure) = injected(fault, SpawnOperation::SpawnAttrInit) {
        return Err(failure);
    }
    let mut attributes = PosixSpawnAttr::init()
        .map_err(|error| SpawnDiagnostic::unavailable(SpawnOperation::SpawnAttrInit, &error))?;
    if let Some(failure) = injected(fault, SpawnOperation::SpawnAttrSetFlags) {
        return Err(failure);
    }
    attributes
        .set_flags(PosixSpawnFlags::empty())
        .map_err(|error| SpawnDiagnostic::unavailable(SpawnOperation::SpawnAttrSetFlags, &error))?;
    if let Some(failure) = injected(fault, SpawnOperation::PosixSpawn) {
        return Err(failure);
    }
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
    .map_err(|error| SpawnDiagnostic::unavailable(SpawnOperation::PosixSpawn, &error));
    drop((control_end, handshake_end, stderr_null, secret_reader));
    let spawned_pid = spawned?;
    let pid = spawned_pid.as_raw();
    match acquire_pidfd(pid) {
        Ok(pidfd) => {
            UnixRetainedWriterProcess::from_spawned(pid, pidfd).map_err(SpawnDiagnostic::from)
        }
        Err(first) => {
            // Bounded cleanup of the OWN unreaped child through the REAL
            // retained kernel handle; no raw-PID fallback, no silent success.
            drop(reserved_fd.take());
            match acquire_pidfd(pid) {
                Ok(pidfd) => {
                    if let Some(_child) = rustix::process::Pid::from_raw(pid) {
                        let _ = rustix::process::pidfd_send_signal(
                            &pidfd,
                            rustix::process::Signal::KILL,
                        );
                        let _ = rustix::process::waitid(
                            rustix::process::WaitId::PidFd(pidfd.as_fd()),
                            rustix::process::WaitIdOptions::EXITED,
                        );
                    }
                    Err(BrokerHandoffError::Rejected.into())
                }
                Err(second) => {
                    drop((first, second, pid));
                    Err(BrokerHandoffError::Rejected.into())
                }
            }
        }
    }
}
