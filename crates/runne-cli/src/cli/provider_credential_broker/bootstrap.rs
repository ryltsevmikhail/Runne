//! Exact pre-Tokio ingress for the daemon-prepared writer endpoint.

use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;

use rustix::io::{FdFlags, fcntl_getfd};
#[cfg(not(target_os = "linux"))]
use rustix::io::fcntl_setfd;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg,
};

use super::CliError;

const DAEMON_ENDPOINT_RESPONSE_BYTES: usize = 160;
const CHANNEL_BINDING: std::ops::Range<usize> = 0..32;
const PUBLICATION_PUBLIC_KEY: std::ops::Range<usize> = 96..128;

/// A one-shot daemon endpoint that cannot expose its received descriptor.
pub struct PreparedDaemonEndpoint {
    #[allow(dead_code)]
    control: OwnedFd,
}

impl PreparedDaemonEndpoint {
    #[cfg(test)]
    pub fn has_close_on_exec(&self) -> bool {
        fcntl_getfd(&self.control)
            .is_ok_and(|flags| flags.contains(FdFlags::CLOEXEC))
    }
}

/// Consumes one exact daemon response inherited as the writer's stdin.
///
/// The response proof bytes are deliberately opaque here: this fixed writer
/// has no transfer authenticator. Daemon peer and release-tuple verification
/// must independently precede the subsequent claim and native effect.
pub fn receive_prepared_daemon_endpoint_from_stdin(
) -> Result<PreparedDaemonEndpoint, CliError> {
    let stdin = std::io::stdin();
    receive_prepared_daemon_endpoint(&mut stdin.lock())
}

pub fn receive_prepared_daemon_endpoint(
    transport: &mut impl std::os::fd::AsFd,
) -> Result<PreparedDaemonEndpoint, CliError> {
    let mut frame = [0; DAEMON_ENDPOINT_RESPONSE_BYTES];
    let mut descriptors = Vec::new();
    let mut received = 0;
    while received < frame.len() {
        let bytes = receive_segment(transport, &mut frame[received..], &mut descriptors)?;
        if bytes == 0 {
            return Err(CliError::CredentialOperation);
        }
        received += bytes;
    }
    require_ancillary_aware_eof(transport, &mut descriptors)?;
    let descriptor = one_descriptor(descriptors)?;
    ensure_close_on_exec(&descriptor)?;
    let channel_binding: [u8; 32] = frame[CHANNEL_BINDING]
        .try_into()
        .map_err(|_| CliError::CredentialOperation)?;
    let publication_public_key: [u8; 32] = frame[PUBLICATION_PUBLIC_KEY]
        .try_into()
        .map_err(|_| CliError::CredentialOperation)?;
    if channel_binding == [0; 32] || publication_public_key == [0; 32] {
        return Err(CliError::CredentialOperation);
    }
    Ok(PreparedDaemonEndpoint {
        control: descriptor,
    })
}

fn receive_segment(
    transport: &mut impl std::os::fd::AsFd,
    bytes: &mut [u8],
    descriptors: &mut Vec<OwnedFd>,
) -> Result<usize, CliError> {
    let mut iov = [std::io::IoSliceMut::new(bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        &mut *transport,
        &mut iov,
        &mut ancillary,
        recv_flags(),
    )
    .map_err(|_| CliError::CredentialOperation)?;
    if received
        .flags
        .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC)
    {
        return Err(CliError::CredentialOperation);
    }
    append_descriptors(&mut ancillary, descriptors)?;
    Ok(received.bytes)
}

fn require_ancillary_aware_eof(
    transport: &mut impl std::os::fd::AsFd,
    descriptors: &mut Vec<OwnedFd>,
) -> Result<(), CliError> {
    let descriptor_count = descriptors.len();
    let mut trailing = [0; 1];
    let bytes = receive_segment(transport, &mut trailing, descriptors)?;
    (bytes == 0 && descriptors.len() == descriptor_count)
        .then_some(())
        .ok_or(CliError::CredentialOperation)
}

const fn recv_flags() -> RecvFlags {
    #[cfg(target_os = "linux")]
    {
        RecvFlags::CMSG_CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        RecvFlags::empty()
    }
}

fn append_descriptors(
    ancillary: &mut RecvAncillaryBuffer<'_>,
    descriptors: &mut Vec<OwnedFd>,
) -> Result<(), CliError> {
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(rights) = message {
            descriptors.extend(rights);
        } else {
            return Err(CliError::CredentialOperation);
        }
    }
    Ok(())
}

fn one_descriptor(mut descriptors: Vec<OwnedFd>) -> Result<OwnedFd, CliError> {
    (descriptors.len() == 1)
        .then(|| descriptors.pop())
        .flatten()
        .ok_or(CliError::CredentialOperation)
}

fn ensure_close_on_exec(descriptor: &OwnedFd) -> Result<(), CliError> {
    #[cfg(not(target_os = "linux"))]
    fcntl_setfd(descriptor, FdFlags::CLOEXEC).map_err(|_| CliError::CredentialOperation)?;
    fcntl_getfd(descriptor)
        .map_err(|_| CliError::CredentialOperation)?
        .contains(FdFlags::CLOEXEC)
        .then_some(())
        .ok_or(CliError::CredentialOperation)
}
