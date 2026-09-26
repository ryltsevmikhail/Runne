//! One-shot Linux Pair relay descriptor transfer in the exclusive V3 relay slot.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use runne_api::LinuxPairSecretRelayOfferAuthenticator;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use sha2::{Digest as _, Sha256};

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::{MacOsAuthenticatedPairSecretRelay, MacOsPairSecretWriter};

const MAGIC: &[u8; 8] = b"GCSFDL01";
const VERSION: u8 = 1;
const BODY_BYTES: usize = 8 + 1 + 32 + 32 + 32 + 1;
const RECORD_BYTES: usize = BODY_BYTES + 32;
const SLOT_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn send(
    relay: MacOsAuthenticatedPairSecretRelay,
    stream: &UnixStream,
    authenticator: &LinuxPairSecretRelayOfferAuthenticator,
    lifecycle_frame: &[u8],
) -> Result<(), BrokerHandoffError> {
    with_slot_timeout(stream, || {
        send_inner(relay, stream, authenticator, lifecycle_frame)
    })
}

fn send_inner(
    relay: MacOsAuthenticatedPairSecretRelay,
    stream: &UnixStream,
    authenticator: &LinuxPairSecretRelayOfferAuthenticator,
    lifecycle_frame: &[u8],
) -> Result<(), BrokerHandoffError> {
    if lifecycle_frame.is_empty() {
        return Err(BrokerHandoffError::Rejected);
    }
    let (channel, publication_key) = relay.sealer.into_public_context();
    if channel == [0; 32] || publication_key == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    let mut frame = [0; RECORD_BYTES];
    frame[..8].copy_from_slice(MAGIC);
    frame[8] = VERSION;
    frame[9..41].copy_from_slice(&Sha256::digest(lifecycle_frame));
    frame[41..73].copy_from_slice(&channel);
    frame[73..105].copy_from_slice(&publication_key);
    frame[105] = 1;
    let proof = authenticator.authenticate_offer(lifecycle_frame, &channel, &publication_key, 1);
    frame[BODY_BYTES..].copy_from_slice(&proof);

    let descriptors = [relay.writer.0.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(BrokerHandoffError::Unavailable);
    }
    let sent = sendmsg(
        stream,
        &[IoSlice::new(&frame)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .map_err(|_| BrokerHandoffError::Unavailable)?;
    (sent == RECORD_BYTES)
        .then_some(())
        .ok_or(BrokerHandoffError::Unavailable)
}

pub(super) fn receive(
    stream: &UnixStream,
    authenticator: &LinuxPairSecretRelayOfferAuthenticator,
    lifecycle_frame: &[u8],
    expected_channel_binding: &[u8; 32],
    expected_publication_key: &[u8; 32],
) -> Result<MacOsAuthenticatedPairSecretRelay, BrokerHandoffError> {
    with_slot_timeout(stream, || {
        receive_inner(
            stream,
            authenticator,
            lifecycle_frame,
            expected_channel_binding,
            expected_publication_key,
        )
    })
}

fn receive_inner(
    stream: &UnixStream,
    authenticator: &LinuxPairSecretRelayOfferAuthenticator,
    lifecycle_frame: &[u8],
    expected_channel_binding: &[u8; 32],
    expected_publication_key: &[u8; 32],
) -> Result<MacOsAuthenticatedPairSecretRelay, BrokerHandoffError> {
    if lifecycle_frame.is_empty() {
        return Err(BrokerHandoffError::Rejected);
    }
    let (frame, descriptor) = receive_record(stream)?;
    let proof: [u8; 32] = frame[BODY_BYTES..]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    if &frame[..8] != MAGIC
        || frame[8] != VERSION
        || frame[9..41] != Sha256::digest(lifecycle_frame)[..]
        || frame[105] != 1
        || frame[41..73] != *expected_channel_binding
        || frame[73..105] != *expected_publication_key
        || frame[41..73] == [0; 32]
        || frame[73..105] == [0; 32]
        || !authenticator.verifies_offer(
            lifecycle_frame,
            &frame[41..73]
                .try_into()
                .map_err(|_| BrokerHandoffError::Rejected)?,
            &frame[73..105]
                .try_into()
                .map_err(|_| BrokerHandoffError::Rejected)?,
            1,
            &proof,
        )
    {
        return Err(BrokerHandoffError::Rejected);
    }
    rustix::io::fcntl_setfd(&descriptor, rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let channel: [u8; 32] = frame[41..73]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let publication_key: [u8; 32] = frame[73..105]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    Ok(MacOsAuthenticatedPairSecretRelay::from_authenticated_parts(
        super::super::macos_secret_sealer::AuthenticatedPairSecretSealer::from_verified_public_context(
            channel,
            publication_key,
        ),
        MacOsPairSecretWriter(std::fs::File::from(descriptor)),
    ))
}

fn receive_record(
    stream: &UnixStream,
) -> Result<([u8; RECORD_BYTES], OwnedFd), BrokerHandoffError> {
    let mut frame = [0; RECORD_BYTES];
    let mut descriptors = Vec::new();
    let mut offset = 0;
    while offset < frame.len() {
        let mut iov = [IoSliceMut::new(&mut frame[offset..])];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let received = recvmsg(stream, &mut iov, &mut ancillary, RecvFlags::empty())
            .map_err(|_| BrokerHandoffError::Unavailable)?;
        if received.bytes == 0
            || received
                .flags
                .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC)
        {
            return Err(BrokerHandoffError::Rejected);
        }
        let had_bytes = offset != 0;
        for message in ancillary.drain() {
            if let RecvAncillaryMessage::ScmRights(rights) = message {
                if had_bytes {
                    return Err(BrokerHandoffError::Rejected);
                }
                descriptors.extend(rights);
            } else {
                return Err(BrokerHandoffError::Rejected);
            }
        }
        offset += received.bytes;
        if offset > 0 && !descriptors.is_empty() && descriptors.len() > 1 {
            return Err(BrokerHandoffError::Rejected);
        }
    }
    let mut descriptors = descriptors.into_iter();
    let descriptor = descriptors.next().ok_or(BrokerHandoffError::Rejected)?;
    if descriptors.next().is_some() {
        return Err(BrokerHandoffError::Rejected);
    }
    let status = rustix::fs::fcntl_getfl(&descriptor).map_err(|_| BrokerHandoffError::Rejected)?;
    let stat = rustix::fs::fstat(&descriptor).map_err(|_| BrokerHandoffError::Rejected)?;
    if status & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::WRONLY
        || !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_fifo()
    {
        return Err(BrokerHandoffError::Rejected);
    }
    Ok((frame, descriptor))
}

fn with_slot_timeout<T>(
    stream: &UnixStream,
    operation: impl FnOnce() -> Result<T, BrokerHandoffError>,
) -> Result<T, BrokerHandoffError> {
    let read_timeout = stream
        .read_timeout()
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let write_timeout = stream
        .write_timeout()
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    stream
        .set_read_timeout(Some(SLOT_TIMEOUT))
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    if stream.set_write_timeout(Some(SLOT_TIMEOUT)).is_err() {
        let _ = stream.set_read_timeout(read_timeout);
        return Err(BrokerHandoffError::Unavailable);
    }
    let result = operation();
    let restore_read = stream.set_read_timeout(read_timeout);
    let restore_write = stream.set_write_timeout(write_timeout);
    if restore_read.is_err() || restore_write.is_err() {
        return Err(BrokerHandoffError::Unavailable);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::PreparedMacOsPairSecretPipe;
    use super::*;
    use crate::provider_credential_broker::macos_secret_sealer::AuthenticatedPairSecretSealer;
    use runne_api::{LaunchSecret, LinuxPairSecretRelayOfferAuthenticator};

    fn setup() -> LinuxPairSecretRelayOfferAuthenticator {
        let keys = LaunchSecret::from_bytes([0x43; 32]).unwrap().derive_keys();
        LinuxPairSecretRelayOfferAuthenticator::from_protected_activation(&keys)
    }

    #[path = "linux_secret_relay_offer/frame_binding_tests.rs"]
    mod frame_binding;

    fn relay() -> (MacOsAuthenticatedPairSecretRelay, OwnedFd) {
        let (reader, writer) = PreparedMacOsPairSecretPipe::prepare().unwrap().into_parts();
        let sealer = AuthenticatedPairSecretSealer::from_verified_public_context([7; 32], [8; 32]);
        (
            MacOsAuthenticatedPairSecretRelay::from_authenticated_parts(sealer, writer),
            reader,
        )
    }

    #[test]
    fn lifecycle_frame_bound_fd_transfer_is_one_shot_and_close_on_exec() {
        let authenticator = setup();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (relay, _reader) = relay();
        let v3_frame = b"validated-v3-relay-frame";
        send(relay, &sender, &authenticator, v3_frame).unwrap();
        let relay = receive(&receiver, &authenticator, v3_frame, &[7; 32], &[8; 32]).unwrap();
        let flags = rustix::io::fcntl_getfd(&relay.writer.0).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    #[test]
    fn different_v3_lifecycle_frame_rejects_and_closes_received_fd() {
        let authenticator = setup();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (relay, _reader) = relay();
        send(relay, &sender, &authenticator, b"frame-one").unwrap();
        assert!(receive(&receiver, &authenticator, b"frame-two", &[7; 32], &[8; 32]).is_err());
    }

    #[test]
    fn foreign_v3_key_cannot_authenticate_relay_offer() {
        let authenticator = setup();
        let foreign_keys = LaunchSecret::from_bytes([0x44; 32]).unwrap().derive_keys();
        let foreign =
            LinuxPairSecretRelayOfferAuthenticator::from_protected_activation(&foreign_keys);
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (relay, _reader) = relay();
        send(relay, &sender, &authenticator, b"frame").unwrap();
        assert!(receive(&receiver, &foreign, b"frame", &[7; 32], &[8; 32]).is_err());
    }

    #[test]
    fn missing_pair_descriptor_fails_closed_on_stream_eof() {
        let authenticator = setup();
        let (sender, receiver) = UnixStream::pair().unwrap();
        drop(sender);
        assert!(
            receive(
                &receiver,
                &authenticator,
                b"validated-frame",
                &[7; 32],
                &[8; 32]
            )
            .is_err()
        );
    }
}
