//! Authenticated Linux writer spawn for non-secret terminal/control claims.

use std::os::unix::net::UnixStream;

use crate::provider_credential_broker::{
    PreparedDaemonWriterEndpointHandoff, UnixRetainedWriterProcess,
};
use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

/// Spawns a signed installed writer without creating or transferring a secret pipe.
///
/// # Errors
///
/// Fails closed on endpoint-transfer proof, bus validation, spawn, or pidfd failure.
pub fn spawn_linux_writer_from_prepared_handoff(
    spec: &VerifiedWriterLaunchSpec,
    prepared: PreparedDaemonWriterEndpointHandoff,
    handshake_end: UnixStream,
    authenticator: &runne_api::CredentialBrokerTransferAuthenticator,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    let control = prepared.into_linux_control_only_parts(authenticator)?;
    let address = super::SessionBusAddress::for_production()?;
    super::spawn_with_secret(
        spec,
        control,
        handshake_end,
        &address,
        None,
        super::open_child_pidfd,
    )
}
