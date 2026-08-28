//! Authenticated daemon-bound writer evidence without descriptor transfer.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use rand::{RngCore, rngs::OsRng};
use runne_api::CredentialBrokerTransferAuthenticator;
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::WriterProcessEvidence;

const CHALLENGE_BYTES: usize = 128;
const RECORD_BYTES: usize = CHALLENGE_BYTES + 96;
const FRAME_BYTES: usize = RECORD_BYTES + 32;
const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const CHALLENGE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-evidence/v1/challenge\0";
const RESPONSE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-evidence/v1/response\0";

/// Sends exact daemon-bound evidence without `SCM_RIGHTS` or another descriptor.
///
/// # Errors
///
/// Returns a closed failure when the challenge, binding, evidence, or proof is invalid.
pub(super) fn send_daemon_owned_writer_evidence(
    mut transport: UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    evidence: &WriterProcessEvidence,
) -> Result<(), BrokerHandoffError> {
    configure(&transport)?;
    let challenge = read_one_shot::<CHALLENGE_BYTES>(&mut transport)?;
    let channel: [u8; 32] = challenge[..32]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let public_key: [u8; 32] = challenge[32..64]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let proof: [u8; 32] = challenge[96..]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    if channel == [0; 32]
        || public_key == [0; 32]
        || !authenticator.verifies_transfer(&transcript(CHALLENGE_TAG, &challenge[..96]), &proof)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let (start, image, release_tuple, evidence_channel, evidence_key) = evidence
        .daemon_handoff_digests()
        .ok_or(BrokerHandoffError::Rejected)?;
    if channel != evidence_channel || public_key != evidence_key {
        return Err(BrokerHandoffError::Rejected);
    }
    let mut record = [0; RECORD_BYTES];
    record[..CHALLENGE_BYTES].copy_from_slice(&challenge);
    record[CHALLENGE_BYTES..160].copy_from_slice(&start);
    record[160..192].copy_from_slice(&image);
    record[192..].copy_from_slice(&release_tuple);
    let proof = authenticator.authenticate_transfer(&transcript(RESPONSE_TAG, &record));
    let mut frame = [0; FRAME_BYTES];
    frame[..RECORD_BYTES].copy_from_slice(&record);
    frame[RECORD_BYTES..].copy_from_slice(&proof);
    transport
        .write_all(&frame)
        .and_then(|()| transport.shutdown(Shutdown::Write))
        .map_err(|_| BrokerHandoffError::Rejected)
}

/// Receives exact daemon-bound evidence without accepting a descriptor.
///
/// # Errors
///
/// Returns a closed failure when the challenge, frame, evidence, or proof is invalid.
pub(super) fn receive_daemon_owned_writer_evidence(
    mut transport: UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    expected_channel: [u8; 32],
    expected_publication_public_key: [u8; 32],
) -> Result<WriterProcessEvidence, BrokerHandoffError> {
    if expected_channel == [0; 32] || expected_publication_public_key == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    configure(&transport)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    challenge[..32].copy_from_slice(&expected_channel);
    challenge[32..64].copy_from_slice(&expected_publication_public_key);
    OsRng
        .try_fill_bytes(&mut challenge[64..96])
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let proof = authenticator.authenticate_transfer(&transcript(CHALLENGE_TAG, &challenge[..96]));
    challenge[96..].copy_from_slice(&proof);
    transport
        .write_all(&challenge)
        .and_then(|()| transport.shutdown(Shutdown::Write))
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let frame = read_one_shot::<FRAME_BYTES>(&mut transport)?;
    let proof: [u8; 32] = frame[RECORD_BYTES..]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    if frame[..CHALLENGE_BYTES] != challenge
        || !authenticator
            .verifies_transfer(&transcript(RESPONSE_TAG, &frame[..RECORD_BYTES]), &proof)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let start = frame[CHALLENGE_BYTES..160]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let image = frame[160..192]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let release_tuple = frame[192..224]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    WriterProcessEvidence::from_daemon_owned_writer(
        start,
        image,
        release_tuple,
        expected_channel,
        expected_publication_public_key,
    )
}

fn read_one_shot<const BYTES: usize>(
    transport: &mut UnixStream,
) -> Result<[u8; BYTES], BrokerHandoffError> {
    let mut received = Vec::with_capacity(BYTES + 1);
    transport
        .take((BYTES + 1) as u64)
        .read_to_end(&mut received)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    received
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)
}

fn configure(stream: &UnixStream) -> Result<(), BrokerHandoffError> {
    stream
        .set_read_timeout(Some(TRANSFER_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TRANSFER_TIMEOUT)))
        .map_err(|_| BrokerHandoffError::Unavailable)
}

fn transcript(tag: &[u8], record: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(tag.len() + record.len());
    transcript.extend_from_slice(tag);
    transcript.extend_from_slice(record);
    transcript
}
