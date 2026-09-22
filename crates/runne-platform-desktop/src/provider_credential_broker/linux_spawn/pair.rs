//! Pair spawn consumes the authenticated handoff and retains one sealed relay.
use std::os::unix::net::UnixStream;

use crate::provider_credential_broker::{
    PreparedDaemonWriterEndpointHandoff, UnixRetainedWriterProcess,
    macos_secret_pipe::{MacOsAuthenticatedPairSecretRelay, PreparedMacOsPairSecretPipe},
};
use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

/// Starts a Pair writer with only its authenticated control/startup sockets.
///
/// The writer also receives one read-only secret pipe. The relay consumes the
/// existing handoff sealer; no caller-supplied publication key or raw secret
/// enters spawn.
///
/// # Errors
/// Fails closed on an invalid endpoint-transfer proof or when the bus, pipe,
/// spawn, or retained pidfd is unavailable.
pub fn spawn_linux_pair_writer_from_prepared_handoff(
    spec: &VerifiedWriterLaunchSpec,
    prepared: PreparedDaemonWriterEndpointHandoff,
    handshake_end: UnixStream,
    authenticator: &runne_api::CredentialBrokerTransferAuthenticator,
) -> Result<(UnixRetainedWriterProcess, MacOsAuthenticatedPairSecretRelay), BrokerHandoffError> {
    let address = super::SessionBusAddress::for_production()?;
    spawn_pair_with_address(spec, prepared, handshake_end, authenticator, &address)
}

fn spawn_pair_with_address(
    spec: &VerifiedWriterLaunchSpec,
    prepared: PreparedDaemonWriterEndpointHandoff,
    handshake_end: UnixStream,
    authenticator: &runne_api::CredentialBrokerTransferAuthenticator,
    address: &super::SessionBusAddress,
) -> Result<(UnixRetainedWriterProcess, MacOsAuthenticatedPairSecretRelay), BrokerHandoffError> {
    let (control, sealer) = prepared.into_linux_pair_spawn_parts(authenticator)?;
    let (reader, writer) = PreparedMacOsPairSecretPipe::prepare()?.into_parts();
    let process = super::spawn_with_secret(
        spec,
        control,
        handshake_end,
        address,
        Some(reader),
        super::open_child_pidfd,
    )?;
    Ok((
        process,
        MacOsAuthenticatedPairSecretRelay::from_authenticated_parts(sealer, writer),
    ))
}

#[cfg(test)]
#[path = "pair_tests.rs"]
mod tests;
