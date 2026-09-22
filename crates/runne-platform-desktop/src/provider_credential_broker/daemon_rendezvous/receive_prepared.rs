//! Finish one already-issued challenge before exposing its received endpoint.
use super::*;

pub(super) fn finish_receive(
    mut transport: UnixStream,
    challenge: [u8; CHALLENGE_BYTES],
    authenticator: &CredentialBrokerTransferAuthenticator,
    expected_binding: [u8; 32],
    expected_publication_public_key: [u8; 32],
) -> Result<UnixReceivedDaemonWriterEndpoint, BrokerHandoffError> {
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
