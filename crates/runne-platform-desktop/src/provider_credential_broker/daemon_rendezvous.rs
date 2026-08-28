//! Authenticated daemon-to-Tauri transfer of a daemon-created writer endpoint.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use rand::{RngCore, rngs::OsRng};
use runne_api::CredentialBrokerTransferAuthenticator;
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::unix_transfer::{receive_descriptor, send_descriptor};

const CHALLENGE_BYTES: usize = 96;
const RESPONSE_BYTES: usize = CHALLENGE_BYTES + 32;
const FRAME_BYTES: usize = RESPONSE_BYTES + 32;
const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const CHALLENGE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-endpoint/v1/challenge\0";
const RESPONSE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-endpoint/v1/response\0";

/// Writer endpoint authenticated as originating from the protected daemon.
///
/// It has no public stream accessor. The platform launcher may only move it to
/// the fixed writer's inherited control descriptor.
pub struct UnixReceivedDaemonWriterEndpoint {
    control: UnixStream,
    channel_binding: [u8; 32],
    publication_public_key: [u8; 32],
}

impl UnixReceivedDaemonWriterEndpoint {
    #[must_use]
    pub const fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    #[must_use]
    pub const fn publication_public_key(&self) -> [u8; 32] {
        self.publication_public_key
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
    mut transport: UnixStream,
    endpoint: UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    expected_binding: [u8; 32],
    publication_public_key: [u8; 32],
) -> Result<(), BrokerHandoffError> {
    if expected_binding == [0; 32] || publication_public_key == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    configure(&transport)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    transport
        .read_exact(&mut challenge)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    require_eof(&mut transport)?;
    let proof: [u8; 32] = challenge[64..]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    if challenge[..32] != expected_binding
        || !authenticator.verifies_transfer(&transcript(CHALLENGE_TAG, &challenge[..64]), &proof)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let mut response = [0; RESPONSE_BYTES];
    response[..CHALLENGE_BYTES].copy_from_slice(&challenge);
    response[CHALLENGE_BYTES..].copy_from_slice(&publication_public_key);
    let response_proof = authenticator.authenticate_transfer(&transcript(RESPONSE_TAG, &response));
    let mut frame = [0; FRAME_BYTES];
    frame[..RESPONSE_BYTES].copy_from_slice(&response);
    frame[RESPONSE_BYTES..].copy_from_slice(&response_proof);
    let result = send_descriptor(&mut transport, &endpoint, &frame).and_then(|()| {
        transport
            .shutdown(Shutdown::Write)
            .map_err(|_| BrokerHandoffError::Rejected)
    });
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
    mut transport: UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    expected_binding: [u8; 32],
    expected_publication_public_key: [u8; 32],
) -> Result<UnixReceivedDaemonWriterEndpoint, BrokerHandoffError> {
    if expected_binding == [0; 32] || expected_publication_public_key == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    configure(&transport)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    challenge[..32].copy_from_slice(&expected_binding);
    OsRng
        .try_fill_bytes(&mut challenge[32..64])
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let proof = authenticator.authenticate_transfer(&transcript(CHALLENGE_TAG, &challenge[..64]));
    challenge[64..].copy_from_slice(&proof);
    transport
        .write_all(&challenge)
        .and_then(|()| transport.shutdown(Shutdown::Write))
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let (frame, descriptor) = receive_descriptor::<FRAME_BYTES>(&mut transport)?;
    require_eof(&mut transport)?;
    let response_proof: [u8; 32] = frame[RESPONSE_BYTES..]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    if frame[..CHALLENGE_BYTES] != challenge
        || frame[CHALLENGE_BYTES..RESPONSE_BYTES] != expected_publication_public_key
        || !authenticator.verifies_transfer(
            &transcript(RESPONSE_TAG, &frame[..RESPONSE_BYTES]),
            &response_proof,
        )
    {
        return Err(BrokerHandoffError::Rejected);
    }
    Ok(UnixReceivedDaemonWriterEndpoint {
        control: UnixStream::from(descriptor),
        channel_binding: expected_binding,
        publication_public_key: expected_publication_public_key,
    })
}

fn configure(transport: &UnixStream) -> Result<(), BrokerHandoffError> {
    transport
        .set_read_timeout(Some(TRANSFER_TIMEOUT))
        .and_then(|()| transport.set_write_timeout(Some(TRANSFER_TIMEOUT)))
        .map_err(|_| BrokerHandoffError::Unavailable)
}

fn require_eof(transport: &mut UnixStream) -> Result<(), BrokerHandoffError> {
    let mut trailing = Vec::new();
    transport
        .take(1)
        .read_to_end(&mut trailing)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    trailing
        .is_empty()
        .then_some(())
        .ok_or(BrokerHandoffError::Rejected)
}

fn transcript(tag: &[u8], record: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(tag.len() + record.len());
    transcript.extend_from_slice(tag);
    transcript.extend_from_slice(record);
    transcript
}
