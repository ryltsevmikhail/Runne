use std::io::Write as _;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use runne_api::{
    CredentialBrokerWriterStartupAuthenticator, ProviderCredentialBrokerTransferAuthority,
    ProviderCredentialEnrollmentHostError as Error,
};

use super::{
    CHALLENGE_BYTES, FRAME_BYTES, LinuxWriterLiveFacts, RECORD_BYTES, RESPONSE_TAG,
    ReceivedWriterProcessMeasurements, TRANSFER_TIMEOUT, configure, read_one_shot, transcript,
};

/// Sends only the writer-scoped key, then verifies one authenticated live-process frame.
///
/// # Errors
///
/// Returns a closed enrollment error when scoped-key derivation, transport I/O,
/// startup proof verification, or live-process validation fails.
pub fn receive_linux_writer_startup(
    mut transport: UnixStream,
    mut authority: ProviderCredentialBrokerTransferAuthority,
    launch_nonce: &[u8; 32],
    expected_release: [u8; 32],
    expected_channel: [u8; 32],
    expected_publication_key: [u8; 32],
    live: LinuxWriterLiveFacts,
) -> Result<[u8; 32], Error> {
    let startup = authority.derive_linux_writer_startup_authenticator(
        *launch_nonce,
        expected_release,
        expected_channel,
        expected_publication_key,
    )?;
    receive_linux_writer_startup_with_authenticator(&mut transport, &mut authority, &startup, live)
}

fn receive_linux_writer_startup_with_authenticator(
    transport: &mut UnixStream,
    authority: &mut ProviderCredentialBrokerTransferAuthority,
    startup: &CredentialBrokerWriterStartupAuthenticator,
    live: LinuxWriterLiveFacts,
) -> Result<[u8; 32], Error> {
    let payload = runne_provider::encode_linux_writer_startup_payload(startup);
    transport
        .set_write_timeout(Some(TRANSFER_TIMEOUT))
        .and_then(|()| transport.set_read_timeout(Some(TRANSFER_TIMEOUT)))
        .map_err(|_| Error::Unavailable)?;
    transport
        .write_all(&*payload)
        .map_err(|_| Error::AccessDenied)?;
    let measurements = receive_startup_measurements(transport, authority, startup)?;
    measurements
        .verified_linux_kill_public_key(live.start_identity, live.image_digest)
        .ok_or(Error::AccessDenied)
}

fn receive_startup_measurements(
    transport: &mut UnixStream,
    authority: &mut ProviderCredentialBrokerTransferAuthority,
    startup: &CredentialBrokerWriterStartupAuthenticator,
) -> Result<ReceivedWriterProcessMeasurements, Error> {
    configure(transport).map_err(|_| Error::Unavailable)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    challenge[..32].copy_from_slice(&startup.channel());
    challenge[32..64].copy_from_slice(&startup.publication_key());
    challenge[64..96].copy_from_slice(&startup.nonce());
    let proof =
        startup.authenticate_daemon_proof(&transcript(super::CHALLENGE_TAG, &challenge[..96]));
    challenge[96..].copy_from_slice(&proof);
    transport
        .write_all(&challenge)
        .and_then(|()| transport.shutdown(Shutdown::Write))
        .map_err(|_| Error::AccessDenied)?;
    let frame = read_one_shot::<FRAME_BYTES>(transport).map_err(|_| Error::AccessDenied)?;
    let response_proof: [u8; 32] = frame[RECORD_BYTES..]
        .try_into()
        .map_err(|_| Error::AccessDenied)?;
    let record: &[u8; RECORD_BYTES] = frame[..RECORD_BYTES]
        .try_into()
        .map_err(|_| Error::AccessDenied)?;
    if frame[..CHALLENGE_BYTES] != challenge
        || !startup.verifies_writer_proof(&transcript(RESPONSE_TAG, record), &response_proof)
    {
        return Err(Error::AccessDenied);
    }
    let witness = authority.verify_linux_writer_startup_evidence(
        record,
        &response_proof,
        startup.release(),
        startup.channel(),
        startup.publication_key(),
        startup,
    )?;
    let start = record[CHALLENGE_BYTES..160]
        .try_into()
        .map_err(|_| Error::AccessDenied)?;
    let image = record[160..192]
        .try_into()
        .map_err(|_| Error::AccessDenied)?;
    let release: [u8; 32] = record[192..224]
        .try_into()
        .map_err(|_| Error::AccessDenied)?;
    let kill_key = record[224..256]
        .try_into()
        .map_err(|_| Error::AccessDenied)?;
    if release != startup.release() || [start, image, release, kill_key].contains(&[0; 32]) {
        return Err(Error::AccessDenied);
    }
    Ok(ReceivedWriterProcessMeasurements {
        start,
        image,
        release_tuple: release,
        channel: startup.channel(),
        publication_public_key: startup.publication_key(),
        writer_kill_public_key: kill_key,
        witness,
    })
}
