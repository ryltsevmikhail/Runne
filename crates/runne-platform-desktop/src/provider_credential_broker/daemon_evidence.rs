#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
//! Authenticated daemon-bound writer evidence without descriptor transfer.

use std::io::Write;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use rand::{RngCore, rngs::OsRng};
use runne_api::{
    CredentialBrokerTransferAuthenticator, ProviderCredentialBrokerTransferAuthority,
    ProviderCredentialBrokerWriterEvidenceWitness,
};
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::WriterProcessEvidence;

mod facts;
#[cfg(target_os = "linux")]
pub use facts::LinuxWriterLiveFacts;
pub use facts::VerifiedWriterMeasurementFacts;
#[path = "daemon_evidence_transfer_io.rs"]
mod daemon_evidence_transfer_io;
#[cfg(test)]
pub(super) use daemon_evidence_transfer_io::transfer_timeout_for_local_test_opt_in;
use daemon_evidence_transfer_io::{configure, read_one_shot, transcript};
#[cfg(target_os = "linux")]
pub use runne_provider::{
    LinuxWriterStartup, encode_linux_writer_startup_payload, linux_writer_self_measurements,
    respond_linux_writer_startup,
};
#[cfg(target_os = "linux")]
#[path = "daemon_evidence/linux_startup.rs"]
mod linux_startup;
#[cfg(target_os = "linux")]
pub use linux_startup::receive_linux_writer_startup;

const CHALLENGE_BYTES: usize = 128;
const RECORD_BYTES: usize = CHALLENGE_BYTES + 128;
const FRAME_BYTES: usize = RECORD_BYTES + 32;
const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const CHALLENGE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-evidence/v1/challenge\0";
const RESPONSE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-evidence/v1/response\0";

/// Untrusted fixed measurements received over one authenticated native transfer.
pub struct ReceivedWriterProcessMeasurements {
    start: [u8; 32],
    image: [u8; 32],
    release_tuple: [u8; 32],
    channel: [u8; 32],
    publication_public_key: [u8; 32],
    writer_kill_public_key: [u8; 32],
    witness: ProviderCredentialBrokerWriterEvidenceWitness,
}

impl ReceivedWriterProcessMeasurements {
    /// Compares every daemon-owned expectation without minting process authority.
    #[must_use]
    pub fn matches_daemon_owned_release(
        &self,
        expected_release_tuple: [u8; 32],
        expected_channel: [u8; 32],
        expected_publication_public_key: [u8; 32],
    ) -> bool {
        self.start != [0; 32]
            && self.image != [0; 32]
            && self.release_tuple == expected_release_tuple
            && self.channel == expected_channel
            && self.publication_public_key == expected_publication_public_key
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn into_macos_peer_witness(self) -> ProviderCredentialBrokerWriterEvidenceWitness {
        self.witness
    }

    #[cfg(test)]
    pub(super) fn matches_launch(
        &self,
        launch: &runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec,
    ) -> bool {
        self.image == launch.artifact().image_digest()
            && self.release_tuple == launch.artifact().release_tuple_digest()
    }
}

impl std::fmt::Debug for ReceivedWriterProcessMeasurements {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReceivedWriterProcessMeasurements(<untrusted-native>)")
    }
}

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
    let (start, image, release_tuple, evidence_channel, evidence_key, writer_kill_public_key) =
        evidence
            .daemon_handoff_digests()
            .ok_or(BrokerHandoffError::Rejected)?;
    if channel != evidence_channel || public_key != evidence_key {
        return Err(BrokerHandoffError::Rejected);
    }
    let mut record = [0; RECORD_BYTES];
    record[..CHALLENGE_BYTES].copy_from_slice(&challenge);
    record[CHALLENGE_BYTES..160].copy_from_slice(&start);
    record[160..192].copy_from_slice(&image);
    record[192..224].copy_from_slice(&release_tuple);
    record[224..].copy_from_slice(&writer_kill_public_key);
    let proof = authenticator.authenticate_transfer(&transcript(RESPONSE_TAG, &record));
    let mut frame = [0; FRAME_BYTES];
    frame[..RECORD_BYTES].copy_from_slice(&record);
    frame[RECORD_BYTES..].copy_from_slice(&proof);
    transport
        .write_all(&frame)
        .and_then(|()| transport.shutdown(Shutdown::Write))
        .map_err(|_| BrokerHandoffError::Rejected)
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn send_test_daemon_owned_writer_evidence(
    transport: UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    measurements: [[u8; 32]; 6],
) -> Result<(), BrokerHandoffError> {
    let [
        start,
        image,
        release_tuple,
        channel,
        publication_public_key,
        writer_kill_public_key,
    ] = measurements;
    let evidence = WriterProcessEvidence::new_daemon_bound(
        start,
        image,
        release_tuple,
        channel,
        publication_public_key,
        writer_kill_public_key,
    )?;
    send_daemon_owned_writer_evidence(transport, authenticator, &evidence)
}

/// Receives exact daemon-bound evidence without accepting a descriptor.
///
/// # Errors
///
/// Returns a closed failure when the challenge, frame, evidence, or proof is invalid.
pub fn receive_daemon_owned_writer_measurements(
    mut transport: UnixStream,
    mut authority: ProviderCredentialBrokerTransferAuthority,
    expected_release_tuple: [u8; 32],
    expected_channel: [u8; 32],
    expected_publication_public_key: [u8; 32],
) -> Result<
    (
        ReceivedWriterProcessMeasurements,
        ProviderCredentialBrokerTransferAuthority,
    ),
    BrokerHandoffError,
> {
    if expected_release_tuple == [0; 32]
        || expected_channel == [0; 32]
        || expected_publication_public_key == [0; 32]
    {
        return Err(BrokerHandoffError::Rejected);
    }
    configure(&transport)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    challenge[..32].copy_from_slice(&expected_channel);
    challenge[32..64].copy_from_slice(&expected_publication_public_key);
    OsRng
        .try_fill_bytes(&mut challenge[64..96])
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let proof =
        authority.authenticate_daemon_transfer(&transcript(CHALLENGE_TAG, &challenge[..96]));
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
        || !authority
            .verifies_desktop_transfer(&transcript(RESPONSE_TAG, &frame[..RECORD_BYTES]), &proof)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let record: &[u8; RECORD_BYTES] = frame[..RECORD_BYTES]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let witness = authority
        .verify_writer_evidence(
            record,
            &proof,
            expected_release_tuple,
            expected_channel,
            expected_publication_public_key,
        )
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let start = frame[CHALLENGE_BYTES..160]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let image = frame[160..192]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let release_tuple: [u8; 32] = frame[192..224]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let measurements = ReceivedWriterProcessMeasurements {
        start,
        image,
        release_tuple: expected_release_tuple,
        channel: expected_channel,
        publication_public_key: expected_publication_public_key,
        writer_kill_public_key: frame[224..256]
            .try_into()
            .map_err(|_| BrokerHandoffError::Rejected)?,
        witness,
    };
    if !measurements.matches_daemon_owned_release(
        expected_release_tuple,
        expected_channel,
        expected_publication_public_key,
    ) || release_tuple != expected_release_tuple
    {
        return Err(BrokerHandoffError::Rejected);
    }
    Ok((measurements, authority))
}
