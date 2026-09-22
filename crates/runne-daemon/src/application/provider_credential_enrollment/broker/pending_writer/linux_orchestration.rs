//! Production Linux writer launch orchestration (B8 stage 4).
//!
//! One caller path: rendezvous facts → the real spawn entry (broker control
//! socket on the child's stdin, private startup socket on stdout) → LIVE
//! pidfd admission remeasure cross-bound with the authenticated startup
//! evidence → `VerifiedLinuxWriterHandshake::into_admitted_writer` with the
//! handshake-delivered REAL kill publication key → the consolidated
//! `LinuxCredentialBrokerChannel`. The startup payload (launch secret ‖
//! release tuple) travels ONLY over the intentionally inherited private
//! startup socket — inherited-descriptor delivery, not encryption. No
//! independent trust key is created anywhere.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the D1 Linux composition slice mounts launch orchestration; tests drive it today"
    )
)]

use std::os::unix::net::UnixStream;

use runne_api::{
    ProviderCredentialBrokerTransferAuthority, ProviderCredentialEnrollmentHostError as Error,
};
use runne_platform_desktop::provider_credential_broker::UnixRetainedWriterProcess;
use runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec;

use super::super::pending::PendingBrokerRendezvousBinding;
use super::super::rendezvous::DaemonBrokerAuthority;
use super::super::unix_linux::LinuxCredentialBrokerChannel;
use super::receive_linux_writer_handshake;

/// How the orchestrator spawns the retained writer. Production uses the
/// real first-party spawn entry; tests may substitute a fault-injectable
/// spawn of the real binary.
pub(crate) type LinuxWriterSpawn =
    Box<dyn FnOnce(UnixStream, UnixStream) -> Result<UnixRetainedWriterProcess, Error>>;

/// Caller-owned inputs for one retained Linux writer launch and handshake.
pub(crate) struct LinuxWriterLaunchInputs {
    /// Daemon-owned rendezvous authority for this exact binding.
    pub(crate) rendezvous: DaemonBrokerAuthority,
    /// Broker control socket half handed to the writer process.
    pub(crate) control_end_for_writer: UnixStream,
    /// Reserved broker rendezvous binding the writer must satisfy.
    pub(crate) binding: PendingBrokerRendezvousBinding,
    /// Transfer authority proving this daemon owns the launch.
    pub(crate) transfer_authority: ProviderCredentialBrokerTransferAuthority,
    /// Private startup secret shared only over the inherited startup socket.
    pub(crate) launch_secret: [u8; 32],
    /// Caller-owned canonical daemon image digest from the build-time
    /// release tuple — never substituted from channel facts.
    pub(crate) daemon_image: [u8; 32],
}

/// Launches one retained writer and drives its verified startup handshake.
///
/// # Errors
///
/// Fails closed on spawn, live admission, or handshake-evidence failure; a
/// failed handshake leaves no session and the caller must terminate the
/// retained writer through its own pidfd authority. `daemon_image` is the
/// caller-owned canonical daemon image digest from the build-time release
/// tuple — never substituted from channel facts.
pub(crate) fn launch_linux_writer_with_handshake(
    inputs: LinuxWriterLaunchInputs,
    spec: &VerifiedWriterLaunchSpec,
    spawn: LinuxWriterSpawn,
) -> Result<LinuxCredentialBrokerChannel, Error> {
    let LinuxWriterLaunchInputs {
        rendezvous,
        control_end_for_writer,
        binding,
        transfer_authority,
        launch_secret,
        daemon_image,
    } = inputs;
    let (handshake_daemon_end, handshake_writer_end) =
        UnixStream::pair().map_err(|_| Error::Unavailable)?;
    let process = spawn(control_end_for_writer, handshake_writer_end)?;
    let expected_release_tuple = binding.release_tuple.as_bytes();
    let handshake = receive_linux_writer_handshake(
        handshake_daemon_end,
        transfer_authority,
        &launch_secret,
        expected_release_tuple,
        &rendezvous,
        &process,
        spec,
    )?;
    let daemon_start =
        LinuxCredentialBrokerChannel::observe_daemon_start().map_err(|_| Error::AccessDenied)?;
    let writer = handshake.into_admitted_writer(binding, rendezvous, process);
    Ok(LinuxCredentialBrokerChannel::from_admitted(
        writer,
        daemon_start,
        daemon_image,
    ))
}
