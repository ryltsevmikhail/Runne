//! Authenticated desktop-to-daemon handoff of one daemon-owned transport half.
//!
//! The desktop creates a socketpair whose daemon half is offered over the
//! already-authenticated protected control channel. The control frames around
//! the raw phase are `ProviderCredentialBrokerHandoffFrame`; this module
//! performs only the fixed-size challenge/response and the `SCM_RIGHTS`
//! transfer on a clone of that channel. Neither side shuts the channel down.

use std::io::{IoSlice, IoSliceMut, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;

use rand::{RngCore, rngs::OsRng};
use runne_api::{CredentialBrokerTransferAuthenticator, ProviderCredentialBrokerTransferAuthority};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

const CHALLENGE_BYTES: usize = 96;
const RECORD_BYTES: usize = CHALLENGE_BYTES + 32;
const FRAME_BYTES: usize = RECORD_BYTES + 32;
const CHALLENGE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-transport/v1/challenge\0";
const RESPONSE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-transport/v1/response\0";

/// Desktop side: answers the daemon challenge with one offered socket half.
///
/// The daemon owns the only receive path; the desktop never observes the
/// descriptor after this point and cannot reclaim the half.
///
/// # Errors
///
/// Returns a closed failure when the challenge, binding, proof, or descriptor
/// transfer fails. The channel keeps its inherited deadlines; no shutdown runs.
pub fn send_daemon_control_transport_half(
    transport: &mut UnixStream,
    half: &UnixStream,
    keys: &CredentialBrokerTransferAuthenticator,
    binding: [u8; 32],
) -> Result<(), BrokerHandoffError> {
    if binding == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    let mut challenge = [0; CHALLENGE_BYTES];
    transport
        .read_exact(&mut challenge)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let proof: [u8; 32] = challenge[64..]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    if challenge[..32] != binding
        || !keys.verifies_transfer(&challenge_transcript(&challenge[..64]), &proof)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    let mut frame = [0; FRAME_BYTES];
    frame[..CHALLENGE_BYTES].copy_from_slice(&challenge);
    frame[CHALLENGE_BYTES..RECORD_BYTES].copy_from_slice(&binding);
    let response_proof =
        keys.authenticate_transfer(&transcript(RESPONSE_TAG, &frame[..RECORD_BYTES]));
    frame[RECORD_BYTES..].copy_from_slice(&response_proof);
    send_half(transport, half, &frame)
}

/// Daemon side: challenges the desktop and receives exactly one socket half.
///
/// The half is marked close-on-exec immediately after receipt so it can never
/// leak across an exec, mirroring the root-handle receive precedent.
///
/// # Errors
///
/// Returns a closed failure when the challenge response, binding, proof, or
/// descriptor transfer fails.
pub fn receive_daemon_control_transport_half(
    transport: &mut UnixStream,
    authority: &ProviderCredentialBrokerTransferAuthority,
    binding: [u8; 32],
) -> Result<UnixStream, BrokerHandoffError> {
    if binding == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    let mut challenge = [0; CHALLENGE_BYTES];
    challenge[..32].copy_from_slice(&binding);
    OsRng
        .try_fill_bytes(&mut challenge[32..64])
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let proof = authority.authenticate_daemon_transfer(&challenge_transcript(&challenge[..64]));
    challenge[64..].copy_from_slice(&proof);
    transport
        .write_all(&challenge)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let (frame, descriptors) = receive_frame(transport)?;
    let response_proof: [u8; 32] = frame[RECORD_BYTES..]
        .try_into()
        .map_err(|_| BrokerHandoffError::Rejected)?;
    if frame[..CHALLENGE_BYTES] != challenge
        || frame[CHALLENGE_BYTES..RECORD_BYTES] != binding
        || !authority.verifies_desktop_transfer(
            &transcript(RESPONSE_TAG, &frame[..RECORD_BYTES]),
            &response_proof,
        )
    {
        return Err(BrokerHandoffError::Rejected);
    }
    one_close_on_exec_half(descriptors)
}

fn challenge_transcript(challenge: &[u8]) -> Vec<u8> {
    transcript(CHALLENGE_TAG, challenge)
}

fn transcript(tag: &[u8], record: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(tag.len() + record.len());
    value.extend_from_slice(tag);
    value.extend_from_slice(record);
    value
}

fn send_half(
    transport: &mut UnixStream,
    half: &UnixStream,
    frame: &[u8; FRAME_BYTES],
) -> Result<(), BrokerHandoffError> {
    let descriptors = [half.as_fd()];
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

fn receive_frame(
    transport: &mut UnixStream,
) -> Result<([u8; FRAME_BYTES], Vec<OwnedFd>), BrokerHandoffError> {
    let mut frame = [0; FRAME_BYTES];
    let mut descriptors = Vec::new();
    let mut offset = 0;
    while offset < frame.len() {
        let received = receive_segment(transport, &mut frame[offset..], &mut descriptors)?;
        if received == 0 {
            return Err(BrokerHandoffError::Rejected);
        }
        offset += received;
    }
    Ok((frame, descriptors))
}

fn receive_segment(
    transport: &mut UnixStream,
    bytes: &mut [u8],
    descriptors: &mut Vec<OwnedFd>,
) -> Result<usize, BrokerHandoffError> {
    let mut iov = [IoSliceMut::new(bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        &mut *transport,
        &mut iov,
        &mut ancillary,
        RecvFlags::empty(),
    )
    .map_err(|_| BrokerHandoffError::Unavailable)?;
    if received
        .flags
        .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(rights) = message {
            descriptors.extend(rights);
        } else {
            return Err(BrokerHandoffError::Rejected);
        }
    }
    Ok(received.bytes)
}

fn one_close_on_exec_half(descriptors: Vec<OwnedFd>) -> Result<UnixStream, BrokerHandoffError> {
    let mut descriptors = descriptors;
    let descriptor = descriptors
        .pop()
        .filter(|_| descriptors.is_empty())
        .ok_or(BrokerHandoffError::Rejected)?;
    // `RecvFlags::CMSG_CLOEXEC` is Linux-only; set close-on-exec portably after
    // receipt so the half can never leak across an exec in the daemon.
    rustix::io::fcntl_setfd(&descriptor, rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    Ok(UnixStream::from(descriptor))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    use runne_api::LaunchSecret;

    fn activation_pair() -> (
        CredentialBrokerTransferAuthenticator,
        ProviderCredentialBrokerTransferAuthority,
    ) {
        let keys = LaunchSecret::from_bytes([31; 32]).unwrap().derive_keys();
        let desktop = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let prelude = runne_api::DaemonEnrollmentLaunchPreludeV1::macos_arm64(
            [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
            [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2],
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            1,
            10,
            20,
        )
        .unwrap();
        let commitment = desktop.enrollment_launch_commitment(&prelude);
        let binding = runne_api::ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
            [4; 32], [6; 32], [8; 32], [5; 32], 1, commitment,
        )
        .unwrap();
        let authority = ProviderCredentialBrokerTransferAuthority::from_enrollment_launch_keys(
            &keys,
            binding.broker_transfer_commitment(),
        );
        (desktop, authority)
    }

    #[test]
    fn transport_offer_round_trips_exactly_one_socket_half() {
        let (desktop, authority) = activation_pair();
        let binding = [9; 32];
        let (mut control_desktop, mut control_daemon) = UnixStream::pair().unwrap();
        let (mut offered_desktop_end, offered_daemon_half) = UnixStream::pair().unwrap();

        let sender = std::thread::spawn(move || {
            send_daemon_control_transport_half(
                &mut control_desktop,
                &offered_daemon_half,
                &desktop,
                binding,
            )
        });
        let mut received =
            receive_daemon_control_transport_half(&mut control_daemon, &authority, binding)
                .unwrap();
        sender.join().unwrap().unwrap();

        // The received half must be the exact offered socket, not a copy.
        std::io::Write::write_all(&mut received, &[7]).unwrap();
        let mut seen = [0; 1];
        std::io::Read::read_exact(&mut offered_desktop_end, &mut seen).unwrap();
        assert_eq!(seen, [7]);
    }

    #[test]
    fn transport_offer_rejects_a_binding_substitution_both_ways() {
        let (desktop, authority) = activation_pair();
        let (mut control_desktop, mut control_daemon) = UnixStream::pair().unwrap();
        let (_, offered_daemon_half) = UnixStream::pair().unwrap();

        let sender = std::thread::spawn(move || {
            send_daemon_control_transport_half(
                &mut control_desktop,
                &offered_daemon_half,
                &desktop,
                [8; 32],
            )
        });
        assert!(
            receive_daemon_control_transport_half(&mut control_daemon, &authority, [9; 32])
                .is_err()
        );
        assert!(sender.join().unwrap().is_err());
    }
}
