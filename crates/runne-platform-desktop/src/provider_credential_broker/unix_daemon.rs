use std::os::unix::net::UnixStream;

use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

use super::unix::{UnixWriterChildChannels, secret_pipe};
use super::{
    RetainedWriterProcess, UnixReceivedDaemonWriterEndpoint, UnixRetainedWriterProcess,
    UnixWriterBrokerEndpoints, WriterProcessEvidence, configure_unix_writer_channels,
    writer_command,
};

impl UnixWriterBrokerEndpoints {
    pub(super) fn from_daemon_control(
        control: UnixStream,
        channel_binding: [u8; 32],
    ) -> Result<(Self, UnixWriterChildChannels), BrokerHandoffError> {
        if channel_binding == [0; 32] {
            return Err(BrokerHandoffError::Rejected);
        }
        let (child_secret, parent_secret) = secret_pipe()?;
        Ok((
            Self {
                control: None,
                secret: Some(parent_secret),
                channel_binding,
            },
            UnixWriterChildChannels {
                control,
                secret: child_secret,
            },
        ))
    }
}

/// Launches the fixed writer with a daemon-owned control endpoint.
///
/// Tauri only moves this endpoint into the child. It cannot read or write the
/// broker channel after receiving it from the authenticated control transport.
///
/// # Errors
///
/// Returns a closed failure when the binding, inherited secret pipe, fixed
/// writer launch, or native process measurement cannot be established.
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
    let (endpoints, child_channels) =
        UnixWriterBrokerEndpoints::from_daemon_control(endpoint.into_control(), channel_binding)?;
    let mut command = writer_command(spec);
    configure_unix_writer_channels(&mut command, child_channels)?;
    let child = command
        .spawn()
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let process = UnixRetainedWriterProcess::from_spawned(child)?;
    let evidence = WriterProcessEvidence::from_native_writer(
        process.writer_start_identity()?,
        spec.artifact().image_digest(),
        channel_binding,
    )?;
    Ok((endpoints, process, evidence))
}
