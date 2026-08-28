//! Authenticated daemon-to-Tauri transfer of a daemon-created writer endpoint.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use rand::{RngCore, rngs::OsRng};
use runne_api::CredentialBrokerTransferAuthenticator;
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::unix_transfer::{receive_descriptor, send_descriptor};

const CHALLENGE_BYTES: usize = 96;
const FRAME_BYTES: usize = CHALLENGE_BYTES + 32;
const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Writer endpoint authenticated as originating from the protected daemon.
///
/// It has no public stream accessor. The platform launcher may only move it to
/// the fixed writer's inherited control descriptor.
pub struct UnixReceivedDaemonWriterEndpoint {
    control: UnixStream,
    channel_binding: [u8; 32],
}

impl UnixReceivedDaemonWriterEndpoint {
    #[must_use]
    pub const fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    pub(super) fn into_control(self) -> UnixStream {
        self.control
    }
}

/// Sends one daemon-created writer endpoint after a receiver-bound challenge.
///
/// # Errors
///
/// Returns a closed failure when the binding, challenge, proof, or descriptor
/// transfer cannot be authenticated and completed exactly once.
pub fn send_daemon_owned_writer_endpoint(
    transport: &mut UnixStream,
    endpoint: UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    expected_binding: [u8; 32],
) -> Result<(), BrokerHandoffError> {
    if expected_binding == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    configure(transport)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    transport
        .read_exact(&mut challenge)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let proof: [u8; 32] = challenge[64..]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    if challenge[..32] != expected_binding
        || !authenticator.verifies_transfer(&challenge[..64], &proof)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let response_proof = authenticator.authenticate_transfer(&challenge);
    let mut frame = [0; FRAME_BYTES];
    frame[..CHALLENGE_BYTES].copy_from_slice(&challenge);
    frame[CHALLENGE_BYTES..].copy_from_slice(&response_proof);
    let result = send_descriptor(transport, &endpoint, &frame);
    drop(endpoint);
    result
}

/// Receives exactly one daemon-created writer endpoint for the expected binding.
///
/// # Errors
///
/// Returns a closed failure when the binding, challenge, proof, or descriptor
/// transfer is missing, altered, stale, or unavailable.
pub fn receive_daemon_owned_writer_endpoint(
    transport: &mut UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    expected_binding: [u8; 32],
) -> Result<UnixReceivedDaemonWriterEndpoint, BrokerHandoffError> {
    if expected_binding == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    configure(transport)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    challenge[..32].copy_from_slice(&expected_binding);
    OsRng
        .try_fill_bytes(&mut challenge[32..64])
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let proof = authenticator.authenticate_transfer(&challenge[..64]);
    challenge[64..].copy_from_slice(&proof);
    transport
        .write_all(&challenge)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let (frame, descriptor) = receive_descriptor::<FRAME_BYTES>(transport)?;
    let response_proof: [u8; 32] = frame[CHALLENGE_BYTES..]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    if frame[..CHALLENGE_BYTES] != challenge
        || !authenticator.verifies_transfer(&challenge, &response_proof)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    Ok(UnixReceivedDaemonWriterEndpoint {
        control: UnixStream::from(descriptor),
        channel_binding: expected_binding,
    })
}

fn configure(transport: &UnixStream) -> Result<(), BrokerHandoffError> {
    transport
        .set_read_timeout(Some(TRANSFER_TIMEOUT))
        .and_then(|()| transport.set_write_timeout(Some(TRANSFER_TIMEOUT)))
        .map_err(|_| BrokerHandoffError::Unavailable)
}
