//! Production Linux writer launch orchestration (B8 stage 4).
//!
//! One caller path: rendezvous facts → the real spawn entry (broker control
//! socket on the child's stdin, private startup socket on stdout) → LIVE
//! pidfd admission remeasure cross-bound with the authenticated startup
//! evidence → `VerifiedLinuxWriterHandshake::into_admitted_writer` with the
//! handshake-delivered REAL kill publication key → the consolidated
//! `LinuxCredentialBrokerChannel`. The startup payload contains a writer-scoped
//! key derived from the transfer authority plus its nonce, release, channel,
//! and publication-key context. It travels ONLY over the intentionally
//! inherited private startup socket — inherited-descriptor delivery, not
//! encryption. The scoped key is not an independent trust root.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the D1 Linux composition slice mounts launch orchestration; tests drive it today"
    )
)]

use std::os::unix::net::UnixStream;

use runne_api::{
    CredentialBrokerTransferAuthenticator, ProviderCredentialBrokerTransferAuthority,
    ProviderCredentialEnrollmentHostError as Error,
};
use runne_platform_desktop::provider_credential_broker::{
    LinuxAuthenticatedPairSecretRelay, UnixRetainedWriterProcess,
};
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

pub(crate) type LinuxControlWriterSpawn = Box<
    dyn FnOnce(
        UnixStream,
        UnixStream,
        &ProviderCredentialBrokerTransferAuthority,
        &CredentialBrokerTransferAuthenticator,
    ) -> Result<UnixRetainedWriterProcess, Error>,
>;

/// Pair spawn also borrows the one Begin-bound transfer proof for the exact
/// daemon-created endpoint and returns ownership of the sealed relay.
pub(crate) type LinuxPairWriterSpawn = Box<
    dyn FnOnce(
        UnixStream,
        UnixStream,
        &ProviderCredentialBrokerTransferAuthority,
        &CredentialBrokerTransferAuthenticator,
    )
        -> Result<(UnixRetainedWriterProcess, LinuxAuthenticatedPairSecretRelay), Error>,
>;

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
    /// Random startup nonce used to derive the writer-scoped key.
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
    );
    let handshake = match handshake {
        Ok(handshake) => handshake,
        Err(error) => {
            use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
            let mut process = process;
            let _ = process.terminate_retained_child();
            let _ = process.reap_retained_child();
            return Err(error);
        }
    };
    let daemon_start = match LinuxCredentialBrokerChannel::observe_daemon_start() {
        Ok(start) => start,
        Err(_) => {
            use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
            let mut process = process;
            let _ = process.terminate_retained_child();
            let _ = process.reap_retained_child();
            return Err(Error::AccessDenied);
        }
    };
    let writer = handshake.into_admitted_writer(binding, rendezvous, process);
    Ok(LinuxCredentialBrokerChannel::from_admitted(
        writer,
        daemon_start,
        daemon_image,
    ))
}

/// Production Pair path: retain the exact writer and one-shot secret relay
/// under daemon ownership, then accept its startup evidence against that child.
pub(crate) fn launch_linux_pair_writer_with_handshake(
    inputs: LinuxWriterLaunchInputs,
    spec: &VerifiedWriterLaunchSpec,
    authenticator: &CredentialBrokerTransferAuthenticator,
    spawn: LinuxPairWriterSpawn,
) -> Result<
    (
        LinuxCredentialBrokerChannel,
        LinuxAuthenticatedPairSecretRelay,
    ),
    Error,
> {
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
    let (process, relay) = spawn(
        control_end_for_writer,
        handshake_writer_end,
        &transfer_authority,
        authenticator,
    )?;
    let handshake = receive_linux_writer_handshake(
        handshake_daemon_end,
        transfer_authority,
        &launch_secret,
        binding.release_tuple.as_bytes(),
        &rendezvous,
        &process,
        spec,
    );
    let handshake = match handshake {
        Ok(handshake) => handshake,
        Err(error) => {
            use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
            let mut process = process;
            let _ = process.terminate_retained_child();
            let _ = process.reap_retained_child();
            return Err(error);
        }
    };
    let daemon_start = match LinuxCredentialBrokerChannel::observe_daemon_start() {
        Ok(start) => start,
        Err(_) => {
            use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
            let mut process = process;
            let _ = process.terminate_retained_child();
            let _ = process.reap_retained_child();
            return Err(Error::AccessDenied);
        }
    };
    let writer = handshake.into_admitted_writer(binding, rendezvous, process);
    Ok((
        LinuxCredentialBrokerChannel::from_admitted(writer, daemon_start, daemon_image),
        relay,
    ))
}

pub(crate) fn launch_linux_control_writer_with_handshake(
    inputs: LinuxWriterLaunchInputs,
    spec: &VerifiedWriterLaunchSpec,
    authenticator: &CredentialBrokerTransferAuthenticator,
    spawn: LinuxControlWriterSpawn,
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
    let process = spawn(
        control_end_for_writer,
        handshake_writer_end,
        &transfer_authority,
        authenticator,
    )?;
    let handshake = receive_linux_writer_handshake(
        handshake_daemon_end,
        transfer_authority,
        &launch_secret,
        binding.release_tuple.as_bytes(),
        &rendezvous,
        &process,
        spec,
    );
    let handshake = match handshake {
        Ok(handshake) => handshake,
        Err(error) => {
            terminate_and_reap(process)?;
            return Err(error);
        }
    };
    let daemon_start = match LinuxCredentialBrokerChannel::observe_daemon_start() {
        Ok(start) => start,
        Err(_) => {
            terminate_and_reap(process)?;
            return Err(Error::AccessDenied);
        }
    };
    let writer = handshake.into_admitted_writer(binding, rendezvous, process);
    Ok(LinuxCredentialBrokerChannel::from_admitted(
        writer,
        daemon_start,
        daemon_image,
    ))
}

fn terminate_and_reap(mut process: UnixRetainedWriterProcess) -> Result<(), Error> {
    use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
    process
        .terminate_retained_child()
        .map_err(|_| Error::Unavailable)?;
    process
        .reap_retained_child()
        .map_err(|_| Error::Unavailable)
}
