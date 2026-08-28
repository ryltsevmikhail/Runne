use std::os::unix::net::UnixStream;

use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

use super::{PreparedDaemonWriterEndpointHandoff, UnixRetainedWriterProcess};

/// Launches the fixed writer with its prepared daemon handoff transport.
///
/// The macOS launch uses an atomic close-on-exec-default spawn profile. Other
/// Unix targets fail closed until they have an equivalent close-other-fds
/// primitive, so no ambient descriptor can reach the writer.
///
/// # Errors
///
/// Returns a closed failure when the exact native launch profile is unavailable.
pub fn spawn_unix_writer_from_prepared_daemon_handoff(
    spec: &VerifiedWriterLaunchSpec,
    prepared: PreparedDaemonWriterEndpointHandoff,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    let (transport, _) = prepared.into_parts();
    spawn_prepared_writer(spec, transport)
}

#[cfg(target_os = "macos")]
fn spawn_prepared_writer(
    spec: &VerifiedWriterLaunchSpec,
    transport: UnixStream,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    super::unix_daemon_macos::spawn_macos_prepared_writer(spec, transport)
}

#[cfg(not(target_os = "macos"))]
fn spawn_prepared_writer(
    _spec: &VerifiedWriterLaunchSpec,
    _transport: UnixStream,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    Err(BrokerHandoffError::Unavailable)
}
