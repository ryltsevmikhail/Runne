use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use gocode_api::RootHandleTransferAuthenticator;
use rand::RngCore;
use rustix::fs::{Mode, OFlags, fstat, open, openat};
#[cfg(target_os = "linux")]
use rustix::fs::{ResolveFlags, openat2};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use sha2::{Digest, Sha256};

use super::{
    RootHandleBrokerError, RootHandleTransferBinding, StableFilesystemIdentity, VerifiedRootHandle,
};

pub(super) type NativeDirectoryHandle = File;
pub(super) type NativeTransferChannel = UnixStream;
const CHALLENGE_BYTES: usize = 96;
const TRANSFER_FRAME_BYTES: usize = 160;
const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

pub(super) fn open_directory(path: &Path) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    let mut current = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RootHandleBrokerError::Rejected)?,
    );
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
    verified_from_handle(current)
}

pub(super) fn open_relative_directory(
    root: &NativeDirectoryHandle,
    path: &Path,
) -> Result<(), RootHandleBrokerError> {
    #[cfg(target_os = "linux")]
    {
        let descriptor = openat2(
            root,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
        .map_err(|_| RootHandleBrokerError::Rejected)?;
        let _ = verified_from_handle(File::from(descriptor))?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        open_relative_portable(root, path)
    }
}

#[cfg(not(target_os = "linux"))]
fn open_relative_portable(
    root: &NativeDirectoryHandle,
    path: &Path,
) -> Result<(), RootHandleBrokerError> {
    let root_device = device(root)?;
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
            if device(&current)? != root_device {
                return Err(RootHandleBrokerError::Rejected);
            }
        }
    }
    let _ = verified_from_handle(current)?;
    Ok(())
}

#[cfg(feature = "test-support")]
pub(super) fn test_pair()
-> Result<(NativeTransferChannel, NativeTransferChannel), RootHandleBrokerError> {
    UnixStream::pair().map_err(|_| RootHandleBrokerError::Unavailable)
}

pub(super) fn send(
    mut stream: NativeTransferChannel,
    root: &VerifiedRootHandle,
    authenticator: &RootHandleTransferAuthenticator,
    binding: &RootHandleTransferBinding,
) -> Result<(), RootHandleBrokerError> {
    configure(&stream)?;
    peer_matches(&stream, binding, binding.receiver_pid)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    stream
        .read_exact(&mut challenge)
        .map_err(|_| RootHandleBrokerError::Rejected)?;
    if challenge[..32] != binding_digest(binding) {
        return Err(RootHandleBrokerError::Rejected);
    }
    let mut receiver_proof = [0; 32];
    receiver_proof.copy_from_slice(&challenge[64..]);
    if !authenticator.verifies_transfer(&challenge[..64], &receiver_proof) {
        return Err(RootHandleBrokerError::Rejected);
    }
    let mut record = [0; 128];
    record[..CHALLENGE_BYTES].copy_from_slice(&challenge);
    record[CHALLENGE_BYTES..].copy_from_slice(&root.identity.digest);
    let proof = authenticator.authenticate_transfer(&record);
    let mut frame = [0; TRANSFER_FRAME_BYTES];
    frame[..128].copy_from_slice(&record);
    frame[128..].copy_from_slice(&proof);
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
    mut stream: NativeTransferChannel,
    authenticator: &RootHandleTransferAuthenticator,
    binding: &RootHandleTransferBinding,
) -> Result<VerifiedRootHandle, RootHandleBrokerError> {
    configure(&stream)?;
    peer_matches(&stream, binding, binding.sender_pid)?;
    let mut challenge = [0; CHALLENGE_BYTES];
    challenge[..32].copy_from_slice(&binding_digest(binding));
    rand::rngs::OsRng.fill_bytes(&mut challenge[32..64]);
    let challenge_proof = authenticator.authenticate_transfer(&challenge[..64]);
    challenge[64..].copy_from_slice(&challenge_proof);
    stream
        .write_all(&challenge)
        .map_err(|_| RootHandleBrokerError::Rejected)?;
    let mut frame = [0; TRANSFER_FRAME_BYTES];
    let mut iov = [IoSliceMut::new(&mut frame)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(&stream, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC)
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
    let mut record = [0; 128];
    record.copy_from_slice(&frame[..128]);
    let mut proof = [0; 32];
    proof.copy_from_slice(&frame[128..]);
    if !authenticator.verifies_transfer(&record, &proof) {
        return Err(RootHandleBrokerError::Rejected);
    }
    let root = verified_from_handle(File::from(descriptor))?;
    if record[..CHALLENGE_BYTES] != challenge || record[CHALLENGE_BYTES..] != root.identity.digest {
        return Err(RootHandleBrokerError::Rejected);
    }
    Ok(root)
}

fn configure(stream: &UnixStream) -> Result<(), RootHandleBrokerError> {
    stream
        .set_read_timeout(Some(TRANSFER_TIMEOUT))
        .map_err(|_| RootHandleBrokerError::Unavailable)?;
    stream
        .set_write_timeout(Some(TRANSFER_TIMEOUT))
        .map_err(|_| RootHandleBrokerError::Unavailable)
}

fn binding_digest(binding: &RootHandleTransferBinding) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode.root-handle-transfer.binding.v1");
    hasher.update(binding.channel_id);
    hasher.update(binding.launch_generation.to_be_bytes());
    hasher.update(binding.sender_pid.to_be_bytes());
    hasher.update(binding.receiver_pid.to_be_bytes());
    hasher.update(binding.peer_uid.to_be_bytes());
    hasher.finalize().into()
}
fn peer_matches(
    stream: &UnixStream,
    binding: &RootHandleTransferBinding,
    expected_pid: u32,
) -> Result<(), RootHandleBrokerError> {
    #[cfg(target_os = "linux")]
    {
        let peer = rustix::net::sockopt::socket_peercred(stream)
            .map_err(|_| RootHandleBrokerError::Rejected)?;
        let peer_pid =
            u32::try_from(peer.pid.as_raw_pid()).map_err(|_| RootHandleBrokerError::Rejected)?;
        if peer_pid != expected_pid || peer.uid.as_raw() as u32 != binding.peer_uid {
            return Err(RootHandleBrokerError::Rejected);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let peer_pid =
            nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerPid)
                .map_err(|_| RootHandleBrokerError::Rejected)
                .and_then(|pid| u32::try_from(pid).map_err(|_| RootHandleBrokerError::Rejected))?;
        let peer_uid =
            nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerCred)
                .map_err(|_| RootHandleBrokerError::Rejected)?;
        if peer_pid != expected_pid || peer_uid.uid() != binding.peer_uid {
            return Err(RootHandleBrokerError::Rejected);
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (stream, binding, expected_pid);
        return Err(RootHandleBrokerError::Unavailable);
    }
    let _ = binding;
    Ok(())
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
    let identity = StableFilesystemIdentity {
        digest: hasher.finalize().into(),
        device: stat.st_dev as u64,
    };
    Ok(VerifiedRootHandle { handle, identity })
}

#[cfg(not(target_os = "linux"))]
fn device(handle: &File) -> Result<u64, RootHandleBrokerError> {
    Ok(fstat(handle)
        .map_err(|_| RootHandleBrokerError::Rejected)?
        .st_dev as u64)
}
