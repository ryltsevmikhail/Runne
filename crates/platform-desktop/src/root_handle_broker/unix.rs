use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Read};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use gocode_api::RootHandleTransferAuthenticator;
use rustix::fs::{Mode, OFlags, fstat, open, openat};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use sha2::{Digest, Sha256};

use super::{
    RootHandleBrokerError, StableFilesystemIdentity, TRANSFER_RECORD_BYTES, VerifiedRootHandle,
    transfer_record,
};

pub(super) type NativeDirectoryHandle = File;
const TRANSFER_FRAME_BYTES: usize = TRANSFER_RECORD_BYTES + 32;

pub(super) fn open_directory(path: &Path) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RootHandleBrokerError::Rejected)?;
    verified_from_handle(File::from(descriptor))
}

pub(super) fn open_relative_directory(
    root: &NativeDirectoryHandle,
    path: &Path,
) -> Result<(), RootHandleBrokerError> {
    let mut current = root
        .try_clone()
        .map_err(|_| RootHandleBrokerError::Rejected)?;
    for component in path.components() {
        if let std::path::Component::Normal(component) = component {
            let descriptor = openat(
                &current,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| RootHandleBrokerError::Rejected)?;
            current = File::from(descriptor);
        }
    }
    let _ = verified_from_handle(current)?;
    Ok(())
}

pub(super) fn send(
    stream: &UnixStream,
    root: &VerifiedRootHandle,
    nonce: [u8; 32],
    authenticator: &RootHandleTransferAuthenticator,
) -> Result<(), RootHandleBrokerError> {
    let record = transfer_record(&nonce, &root.identity);
    let proof = authenticator.authenticate_transfer(&record);
    let mut frame = [0; TRANSFER_FRAME_BYTES];
    frame[..TRANSFER_RECORD_BYTES].copy_from_slice(&record);
    frame[TRANSFER_RECORD_BYTES..].copy_from_slice(&proof);
    let descriptors = [root.handle.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(RootHandleBrokerError::Unavailable);
    }
    let sent = sendmsg(
        stream,
        &[IoSlice::new(&frame)],
        &mut control,
        SendFlags::empty(),
    )
    .map_err(|_| RootHandleBrokerError::Unavailable)?;
    (sent == frame.len())
        .then_some(())
        .ok_or(RootHandleBrokerError::Unavailable)
}

pub(super) fn receive(
    stream: &UnixStream,
    authenticator: &RootHandleTransferAuthenticator,
) -> Result<(VerifiedRootHandle, [u8; 32]), RootHandleBrokerError> {
    let mut frame = [0; TRANSFER_FRAME_BYTES];
    let mut iov = [IoSliceMut::new(&mut frame)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(stream, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC)
        .map_err(|_| RootHandleBrokerError::Unavailable)?;
    if received.bytes == 0 || received.flags.intersects(rustix::net::ReturnFlags::CTRUNC) {
        return Err(RootHandleBrokerError::Rejected);
    }
    let descriptor = received_descriptor(&mut control)?;
    if received.bytes < frame.len() {
        let mut remaining = stream;
        remaining
            .read_exact(&mut frame[received.bytes..])
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
    }
    let mut record = [0; TRANSFER_RECORD_BYTES];
    record.copy_from_slice(&frame[..TRANSFER_RECORD_BYTES]);
    let mut proof = [0; 32];
    proof.copy_from_slice(&frame[TRANSFER_RECORD_BYTES..]);
    if !authenticator.verifies_transfer(&record, &proof) {
        return Err(RootHandleBrokerError::Rejected);
    }
    let root = verified_from_handle(File::from(descriptor))?;
    if transfer_record(
        &record[..32]
            .try_into()
            .map_err(|_| RootHandleBrokerError::Rejected)?,
        &root.identity,
    ) != record
    {
        return Err(RootHandleBrokerError::Rejected);
    }
    let nonce = record[..32]
        .try_into()
        .map_err(|_| RootHandleBrokerError::Rejected)?;
    Ok((root, nonce))
}

fn received_descriptor(
    control: &mut RecvAncillaryBuffer<'_>,
) -> Result<OwnedFd, RootHandleBrokerError> {
    let mut descriptors = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(rights) = message {
            descriptors.extend(rights);
        } else {
            return Err(RootHandleBrokerError::Rejected);
        }
    }
    (descriptors.len() == 1)
        .then(|| descriptors.pop())
        .flatten()
        .ok_or(RootHandleBrokerError::Rejected)
}

fn verified_from_handle(handle: File) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    if !handle
        .metadata()
        .map_err(|_| RootHandleBrokerError::Rejected)?
        .is_dir()
    {
        return Err(RootHandleBrokerError::Rejected);
    }
    let stat = fstat(&handle).map_err(|_| RootHandleBrokerError::Rejected)?;
    let mut hasher = Sha256::new();
    hasher.update((stat.st_dev as u64).to_be_bytes());
    hasher.update((stat.st_ino as u64).to_be_bytes());
    let identity = StableFilesystemIdentity(hasher.finalize().into());
    Ok(VerifiedRootHandle { handle, identity })
}
