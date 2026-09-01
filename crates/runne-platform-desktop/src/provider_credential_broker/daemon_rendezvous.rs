#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
//! Authenticated daemon-to-Tauri transfer of a daemon-created writer endpoint.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use rand::{RngCore, rngs::OsRng};
use runne_api::{CredentialBrokerTransferAuthenticator, ProviderCredentialBrokerTransferAuthority};
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
use sha2::{Digest as _, Sha256};

use super::unix_descriptor::{receive_descriptor, send_descriptor};

const CHALLENGE_BYTES: usize = 96;
const RESPONSE_BYTES: usize = CHALLENGE_BYTES + 32;
const FRAME_BYTES: usize = RESPONSE_BYTES + 32;
const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const CHALLENGE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-endpoint/v1/challenge\0";
const RESPONSE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-endpoint/v1/response\0";
const HANDOFF_DOMAIN: &[u8] = b"GOCODE_WRITER_ENDPOINT_HANDOFF_V1\0";

/// Exact descriptor-transfer transcript constructed by the authenticated daemon sender.
pub struct VerifiedDaemonWriterEndpointHandoffFacts {
    digest: [u8; 32],
}

impl VerifiedDaemonWriterEndpointHandoffFacts {
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub const fn test_only(digest: [u8; 32]) -> Self {
        Self { digest }
    }
}

/// Writer endpoint authenticated as originating from the protected daemon.
///
/// It has no public stream accessor. It remains a Linux-only protocol-test
/// primitive; it is not a writer launch input.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct UnixReceivedDaemonWriterEndpoint {
    control: UnixStream,
    channel_binding: [u8; 32],
    publication_public_key: [u8; 32],
}

/// A prepared one-shot handoff transport for one fixed writer.
///
/// Tauri only sends an authenticated outbound challenge and closes its write
/// half. It does not observe or authenticate the daemon's later response. The
/// opaque transport can be consumed once by the fixed writer launcher before
/// that writer creates any threads.
pub struct PreparedDaemonWriterEndpointHandoff {
    transport: UnixStream,
    challenge: [u8; CHALLENGE_BYTES],
    channel_binding: [u8; 32],
    publication_public_key: [u8; 32],
}

impl PreparedDaemonWriterEndpointHandoff {
    pub(super) fn into_receive_parts(self) -> (UnixStream, [u8; CHALLENGE_BYTES]) {
        (self.transport, self.challenge)
    }

    pub(super) fn into_spawn_parts(self) -> (UnixStream, [u8; 32], [u8; 32]) {
        (
            self.transport,
            self.channel_binding,
            self.publication_public_key,
        )
    }

    #[cfg(target_os = "macos")]
    pub(super) fn into_pair_spawn_parts(
        self,
    ) -> Result<
        (
            UnixStream,
            [u8; 32],
            [u8; 32],
            super::macos_secret_sealer::AuthenticatedPairSecretSealer,
        ),
        BrokerHandoffError,
    > {
        let sealer = super::macos_secret_sealer::AuthenticatedPairSecretSealer::from_handoff(
            self.publication_public_key,
            self.channel_binding,
        )?;
        Ok((
            self.transport,
            self.channel_binding,
            self.publication_public_key,
            sealer,
        ))
    }
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

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
    authority: &ProviderCredentialBrokerTransferAuthority,
    expected_binding: [u8; 32],
    publication_public_key: [u8; 32],
) -> Result<VerifiedDaemonWriterEndpointHandoffFacts, BrokerHandoffError> {
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
        || !authority.verifies_desktop_transfer(
            &challenge_transcript(&challenge[..64], publication_public_key),
            &proof,
        )
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let mut response = [0; RESPONSE_BYTES];
    response[..CHALLENGE_BYTES].copy_from_slice(&challenge);
    response[CHALLENGE_BYTES..].copy_from_slice(&publication_public_key);
    let response_proof =
        authority.authenticate_daemon_transfer(&transcript(RESPONSE_TAG, &response));
    let mut frame = [0; FRAME_BYTES];
    frame[..RESPONSE_BYTES].copy_from_slice(&response);
    frame[RESPONSE_BYTES..].copy_from_slice(&response_proof);
    let result = send_descriptor(&mut transport, &endpoint, &frame).and_then(|()| {
        transport
            .shutdown(Shutdown::Write)
            .map_err(|_| BrokerHandoffError::Rejected)
    });
    drop(endpoint);
    result.map(|()| {
        let mut digest = Sha256::new();
        digest.update(HANDOFF_DOMAIN);
        digest.update(frame);
        VerifiedDaemonWriterEndpointHandoffFacts {
            digest: digest.finalize().into(),
        }
    })
}

/// Receives exactly one daemon-created writer endpoint for the expected binding.
///
/// # Errors
///
/// Returns a closed failure when the binding, challenge, proof, or descriptor
/// transfer is missing, altered, stale, or unavailable.
pub fn receive_daemon_owned_writer_endpoint(
    transport: UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    expected_binding: [u8; 32],
    expected_publication_public_key: [u8; 32],
) -> Result<UnixReceivedDaemonWriterEndpoint, BrokerHandoffError> {
    let prepared = prepare_daemon_owned_writer_endpoint_handoff(
        transport,
        authenticator,
        expected_binding,
        expected_publication_public_key,
    )?;
    let (mut transport, challenge) = prepared.into_receive_parts();
    let (frame, descriptor) = receive_descriptor::<FRAME_BYTES>(&mut transport)?;
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

/// Authenticates the one-shot challenge without receiving the daemon endpoint.
///
/// The resulting opaque transport is only suitable for direct inheritance by
/// the fixed writer. Calling the full receiver instead remains unavailable on
/// macOS because receiving a descriptor in the multithreaded desktop would
/// require a racy post-receive close-on-exec operation.
///
/// # Errors
///
/// Returns a closed failure when the expected binding/key are absent or the
/// authenticated challenge cannot be written and half-closed exactly once.
pub fn prepare_daemon_owned_writer_endpoint_handoff(
    mut transport: UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    expected_binding: [u8; 32],
    expected_publication_public_key: [u8; 32],
) -> Result<PreparedDaemonWriterEndpointHandoff, BrokerHandoffError> {
    if expected_binding == [0; 32] || expected_publication_public_key == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    configure(&transport)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    challenge[..32].copy_from_slice(&expected_binding);
    OsRng
        .try_fill_bytes(&mut challenge[32..64])
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let proof = authenticator.authenticate_transfer(&challenge_transcript(
        &challenge[..64],
        expected_publication_public_key,
    ));
    challenge[64..].copy_from_slice(&proof);
    transport
        .write_all(&challenge)
        .and_then(|()| transport.shutdown(Shutdown::Write))
        .map_err(|_| BrokerHandoffError::Rejected)?;
    Ok(PreparedDaemonWriterEndpointHandoff {
        transport,
        challenge,
        channel_binding: expected_binding,
        publication_public_key: expected_publication_public_key,
    })
}

fn challenge_transcript(challenge: &[u8], publication_public_key: [u8; 32]) -> Vec<u8> {
    let mut result = transcript(CHALLENGE_TAG, challenge);
    result.extend_from_slice(&publication_public_key);
    result
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
