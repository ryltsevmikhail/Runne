use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

use super::{
    RetainedWriterProcess, UnixReceivedDaemonWriterEndpoint, UnixRetainedWriterProcess,
    UnixWriterBrokerEndpoints, WriterProcessEvidence, writer_command,
};

impl UnixWriterBrokerEndpoints {
    pub(super) fn from_daemon_control(
        channel_binding: [u8; 32],
    ) -> Result<Self, BrokerHandoffError> {
        if channel_binding == [0; 32] {
            return Err(BrokerHandoffError::Rejected);
        }
        Ok(Self {
            control: None,
            secret: None,
            channel_binding,
        })
    }
}

fn configure_daemon_owned_writer_control(
    command: &mut Command,
    control: UnixStream,
) -> Result<(), BrokerHandoffError> {
    let control_stderr = control
        .try_clone()
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    command.stdin(Stdio::from(OwnedFd::from(control)));
    command.stderr(Stdio::from(OwnedFd::from(control_stderr)));
    command.stdout(Stdio::null());
    Ok(())
}

/// Launches the fixed writer with a daemon-owned control endpoint.
///
/// Tauri only moves this endpoint into the child. It cannot read or write the
/// broker channel after receiving it from the authenticated control transport.
///
/// # Errors
///
/// Returns a closed failure when the binding, inherited control endpoint,
/// fixed writer launch, or native process measurement cannot be established.
pub fn spawn_unix_writer_from_daemon_endpoint(
    spec: &VerifiedWriterLaunchSpec,
    endpoint: UnixReceivedDaemonWriterEndpoint,
) -> Result<
    (
        UnixWriterBrokerEndpoints,
        UnixRetainedWriterProcess,
        WriterProcessEvidence,
    ),
    BrokerHandoffError,
> {
    let channel_binding = endpoint.channel_binding();
    let publication_public_key = endpoint.publication_public_key();
    let endpoints = UnixWriterBrokerEndpoints::from_daemon_control(channel_binding)?;
    let mut command = writer_command(spec);
    configure_daemon_owned_writer_control(&mut command, endpoint.into_control())?;
    let child = command
        .spawn()
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let process = UnixRetainedWriterProcess::from_spawned(child)?;
    let evidence = WriterProcessEvidence::from_daemon_owned_writer(
        process.writer_start_identity()?,
        spec.artifact().image_digest(),
        spec.artifact().release_tuple_digest(),
        channel_binding,
        publication_public_key,
    )?;
    Ok((endpoints, process, evidence))
}
