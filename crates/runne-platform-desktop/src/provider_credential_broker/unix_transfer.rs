//! Authenticated one-shot transfer of a writer control endpoint.

use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;

use rand::RngCore;
use runne_api::CredentialBrokerTransferAuthenticator;
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

use super::{UnixWriterBrokerEndpoints, WriterProcessEvidence};

const CHALLENGE_BYTES: usize = 96;
const RECORD_BYTES: usize = CHALLENGE_BYTES + 96;
const FRAME_BYTES: usize = RECORD_BYTES + 32;
const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Daemon-owned control endpoint and the platform-issued child evidence.
pub struct UnixReceivedWriterControl {
    control: UnixStream,
    evidence: WriterProcessEvidence,
}

impl UnixReceivedWriterControl {
    #[must_use]
    pub const fn channel_binding(&self) -> [u8; 32] {
        self.evidence.handoff_digests().2
    }

    #[must_use]
    pub fn into_parts(self) -> (UnixStream, WriterProcessEvidence) {
        (self.control, self.evidence)
    }
}

/// Sends Tauri's control descriptor after proving a fresh receiver challenge.
///
/// The secret pipe is intentionally not part of this transfer. A failed send
/// closes the local control endpoint instead of risking a duplicate owner.
///
/// # Errors
///
/// Returns a closed failure if the challenge, proof, evidence, or native send
/// cannot be completed exactly once.
pub fn transfer_unix_writer_control(
    transport: &mut UnixStream,
    endpoints: &mut UnixWriterBrokerEndpoints,
    authenticator: &CredentialBrokerTransferAuthenticator,
    evidence: &WriterProcessEvidence,
) -> Result<(), BrokerHandoffError> {
    configure(transport)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    transport
        .read_exact(&mut challenge)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let (_, _, channel) = evidence.handoff_digests();
    let receiver_proof =
        <[u8; 32]>::try_from(&challenge[64..]).map_err(|_| BrokerHandoffError::Rejected)?;
    if challenge[..32] != channel
        || !authenticator.verifies_transfer(&challenge[..64], &receiver_proof)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let (start, image, channel) = evidence.handoff_digests();
    let mut record = [0; RECORD_BYTES];
    record[..CHALLENGE_BYTES].copy_from_slice(&challenge);
    record[CHALLENGE_BYTES..128].copy_from_slice(&start);
    record[128..160].copy_from_slice(&image);
    record[160..].copy_from_slice(&channel);
    let proof = authenticator.authenticate_transfer(&record);
    let mut frame = [0; FRAME_BYTES];
    frame[..RECORD_BYTES].copy_from_slice(&record);
    frame[RECORD_BYTES..].copy_from_slice(&proof);
    let control_endpoint = endpoints.take_control_for_handoff()?;
    send_descriptor(transport, &control_endpoint, &frame)
}

/// Receives exactly one writer control descriptor bound to a fresh challenge.
///
/// The outer protected transport must authenticate the logical native peers;
/// inherited socket-pair kernel peer credentials identify the creator, not the
/// exec'd writer, and are therefore deliberately not used here.
///
/// # Errors
///
/// Returns a closed failure for a stale, altered, mismatched, or malformed
/// descriptor transfer.
pub fn receive_unix_writer_control(
    transport: &mut UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    expected_channel: [u8; 32],
) -> Result<UnixReceivedWriterControl, BrokerHandoffError> {
    if expected_channel == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    configure(transport)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    challenge[..32].copy_from_slice(&expected_channel);
    rand::rngs::OsRng.fill_bytes(&mut challenge[32..64]);
    let challenge_proof = authenticator.authenticate_transfer(&challenge[..64]);
    challenge[64..].copy_from_slice(&challenge_proof);
    transport
        .write_all(&challenge)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let (frame, descriptor) = receive_descriptor(transport)?;
    let mut record = [0; RECORD_BYTES];
    record.copy_from_slice(&frame[..RECORD_BYTES]);
    let proof =
        <[u8; 32]>::try_from(&frame[RECORD_BYTES..]).map_err(|_| BrokerHandoffError::Rejected)?;
    if !authenticator.verifies_transfer(&record, &proof) || record[..CHALLENGE_BYTES] != challenge {
        return Err(BrokerHandoffError::Rejected);
    }
    let start = <[u8; 32]>::try_from(&record[CHALLENGE_BYTES..128])
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let image =
        <[u8; 32]>::try_from(&record[128..160]).map_err(|_| BrokerHandoffError::Rejected)?;
    let channel = <[u8; 32]>::try_from(&record[160..]).map_err(|_| BrokerHandoffError::Rejected)?;
    if channel != expected_channel {
        return Err(BrokerHandoffError::Rejected);
    }
    let evidence = WriterProcessEvidence::from_native_writer(start, image, channel)?;
    Ok(UnixReceivedWriterControl {
        control: UnixStream::from(descriptor),
        evidence,
    })
}

fn configure(stream: &UnixStream) -> Result<(), BrokerHandoffError> {
    stream
        .set_read_timeout(Some(TRANSFER_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TRANSFER_TIMEOUT)))
        .map_err(|_| BrokerHandoffError::Unavailable)
}

fn send_descriptor(
    transport: &mut UnixStream,
    control_endpoint: &UnixStream,
    frame: &[u8; FRAME_BYTES],
) -> Result<(), BrokerHandoffError> {
    let descriptors = [control_endpoint.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(BrokerHandoffError::Unavailable);
    }
    let sent = sendmsg(
        transport,
        &[IoSlice::new(frame)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .map_err(|_| BrokerHandoffError::Unavailable)?;
    (sent == frame.len())
        .then_some(())
        .ok_or(BrokerHandoffError::Unavailable)
}

fn receive_descriptor(
    transport: &mut UnixStream,
) -> Result<([u8; FRAME_BYTES], OwnedFd), BrokerHandoffError> {
    let mut frame = [0; FRAME_BYTES];
    let mut iov = [IoSliceMut::new(&mut frame)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        &mut *transport,
        &mut iov,
        &mut ancillary,
        RecvFlags::empty(),
    )
    .map_err(|_| BrokerHandoffError::Unavailable)?;
    if received.bytes == 0 || received.flags.intersects(rustix::net::ReturnFlags::CTRUNC) {
        return Err(BrokerHandoffError::Rejected);
    }
    let descriptor = received_descriptor(&mut ancillary)?;
    fcntl_setfd(&descriptor, FdFlags::CLOEXEC).map_err(|_| BrokerHandoffError::Unavailable)?;
    if received.bytes < frame.len() {
        transport
            .read_exact(&mut frame[received.bytes..])
            .map_err(|_| BrokerHandoffError::Unavailable)?;
    }
    Ok((frame, descriptor))
}

fn received_descriptor(
    ancillary: &mut RecvAncillaryBuffer<'_>,
) -> Result<OwnedFd, BrokerHandoffError> {
    let mut descriptors = Vec::new();
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(rights) = message {
            descriptors.extend(rights);
        } else {
            return Err(BrokerHandoffError::Rejected);
        }
    }
    (descriptors.len() == 1)
        .then(|| descriptors.pop())
        .flatten()
        .ok_or(BrokerHandoffError::Rejected)
}
