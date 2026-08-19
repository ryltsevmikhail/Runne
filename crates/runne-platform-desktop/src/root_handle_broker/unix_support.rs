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
    hasher.update(b"runne.root-handle-transfer.binding.v1");
    hasher.update(binding.channel_id);
    hasher.update(binding.launch_generation.to_be_bytes());
    hasher.update(binding.sender_pid.to_be_bytes());
    hasher.update(binding.receiver_pid.to_be_bytes());
    hasher.update(binding.peer_uid.to_be_bytes());
    hasher.update(binding.offer_digest);
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
        let pid = u32::try_from(peer.pid.as_raw_pid()).map_err(|_| RootHandleBrokerError::Rejected)?;
        if pid != expected_pid || peer.uid.as_raw() as u32 != binding.peer_uid {
            return Err(RootHandleBrokerError::Rejected);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let pid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerPid)
            .map_err(|_| RootHandleBrokerError::Rejected)
            .and_then(|value| u32::try_from(value).map_err(|_| RootHandleBrokerError::Rejected))?;
        let credentials = nix::sys::socket::getsockopt(
            stream,
            nix::sys::socket::sockopt::LocalPeerCred,
        )
        .map_err(|_| RootHandleBrokerError::Rejected)?;
        if pid != expected_pid || credentials.uid() != binding.peer_uid {
            return Err(RootHandleBrokerError::Rejected);
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (stream, binding, expected_pid);
        return Err(RootHandleBrokerError::Unavailable);
    }
    Ok(())
}

fn received_descriptor(
    control: &mut RecvAncillaryBuffer<'_>,
) -> Result<OwnedFd, RootHandleBrokerError> {
    let mut values = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(rights) = message {
            values.extend(rights);
        } else {
            return Err(RootHandleBrokerError::Rejected);
        }
    }
    (values.len() == 1)
        .then(|| values.pop())
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
    #[allow(clippy::useless_conversion)]
    let device = u64::try_from(stat.st_dev).map_err(|_| RootHandleBrokerError::Rejected)?;
    let mut hasher = Sha256::new();
    hasher.update(device.to_be_bytes());
    hasher.update((stat.st_ino as u64).to_be_bytes());
    Ok(VerifiedRootHandle {
        handle,
        identity: StableFilesystemIdentity {
            digest: hasher.finalize().into(),
            device,
        },
    })
}

#[cfg(not(target_os = "linux"))]
fn device(handle: &File) -> Result<u64, RootHandleBrokerError> {
    u64::try_from(
        fstat(handle)
            .map_err(|_| RootHandleBrokerError::Rejected)?
            .st_dev,
    )
    .map_err(|_| RootHandleBrokerError::Rejected)
}
