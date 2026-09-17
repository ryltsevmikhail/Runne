#![cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]

use super::*;

/// Owned daemon side of the inherited full-duplex activation channel.
#[cfg(unix)]
pub struct ProtectedActivationChannel {
    stream: std::os::unix::net::UnixStream,
}

#[cfg(windows)]
pub struct ProtectedActivationChannel {
    stream: std::fs::File,
}

#[cfg(windows)]
impl ProtectedActivationChannel {
    pub(crate) fn new(stream: std::fs::File) -> Result<Self, LaunchAuthorityError> {
        Ok(Self { stream })
    }

    pub fn from_inherited_stdin() -> Result<Option<Self>, LaunchAuthorityError> {
        crate::protected_activation::windows_channel::from_inherited_stdin()
    }

    pub(super) fn read_frame(&mut self) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
        read_file_frame(&mut self.stream)
    }

    pub(super) fn write_frame(&mut self, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
        write_file_frame(&mut self.stream, frame)
    }

    pub(crate) fn read_control_frame(
        &mut self,
    ) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
        self.read_frame()
    }

    pub(crate) fn write_control_frame(&mut self, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
        self.write_frame(frame)
    }

    #[cfg(any(feature = "desktop-protected", feature = "test-support"))]
    pub(super) fn enter_control_loop(&self) -> Result<(), LaunchAuthorityError> {
        Ok(())
    }
}

#[cfg(windows)]
fn read_file_frame(stream: &mut std::fs::File) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
    let mut prefix = [0; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
    let payload_length = u32::from_be_bytes(prefix) as usize;
    if payload_length == 0 || payload_length > MAX_FRAME_PAYLOAD_BYTES {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    let frame_length = payload_length
        .checked_add(4)
        .ok_or(LaunchAuthorityError::InvalidContract)?;
    let mut frame = vec![0; frame_length];
    frame[..4].copy_from_slice(&prefix);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
    Ok(Zeroizing::new(frame))
}

#[cfg(windows)]
fn write_file_frame(stream: &mut std::fs::File, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
    if frame.len() < 5
        || frame.len() > MAX_FRAME_PAYLOAD_BYTES + 4
        || u32::from_be_bytes(frame[..4].try_into().unwrap_or([0; 4])) as usize != frame.len() - 4
    {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)
}

#[cfg(unix)]
impl ProtectedActivationChannel {
    /// Wraps the inherited child endpoint and installs bounded I/O deadlines.
    pub(crate) fn new(
        stream: std::os::unix::net::UnixStream,
    ) -> Result<Self, LaunchAuthorityError> {
        stream
            .set_read_timeout(Some(CHANNEL_TIMEOUT))
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        stream
            .set_write_timeout(Some(CHANNEL_TIMEOUT))
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        Ok(Self { stream })
    }

    /// Duplicates stdin only when it is a Unix-domain socket.
    pub fn from_inherited_stdin() -> Result<Option<Self>, LaunchAuthorityError> {
        use std::os::fd::AsFd as _;

        let owned = rustix::io::dup(std::io::stdin().as_fd())
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        let stream = std::os::unix::net::UnixStream::from(owned);
        match stream.peer_addr() {
            Ok(_) => Self::new(stream).map(Some),
            Err(error)
                if error.raw_os_error() == Some(libc::ENOTSOCK)
                    || error.raw_os_error() == Some(libc::EINVAL) =>
            {
                Ok(None)
            }
            Err(_) => Err(LaunchAuthorityError::ProtectedChannelUnavailable),
        }
    }

    pub(super) fn read_frame(&mut self) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
        let mut prefix = [0; 4];
        self.stream
            .read_exact(&mut prefix)
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        let payload_length = u32::from_be_bytes(prefix) as usize;
        if payload_length == 0 || payload_length > MAX_FRAME_PAYLOAD_BYTES {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let frame_length = payload_length
            .checked_add(4)
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        let mut frame = vec![0; frame_length];
        frame[..4].copy_from_slice(&prefix);
        self.stream
            .read_exact(&mut frame[4..])
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        Ok(Zeroizing::new(frame))
    }

    pub(super) fn write_frame(&mut self, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
        if frame.len() < 5
            || frame.len() > MAX_FRAME_PAYLOAD_BYTES + 4
            || u32::from_be_bytes(frame[..4].try_into().unwrap_or([0; 4])) as usize
                != frame.len() - 4
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.stream
            .write_all(frame)
            .and_then(|()| self.stream.flush())
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)
    }

    #[cfg(all(unix, feature = "desktop-protected"))]
    pub(super) const fn unix_stream(&self) -> &std::os::unix::net::UnixStream {
        &self.stream
    }

    /// Reads the next bounded frame for the post-readiness control loop.
    pub(crate) fn read_control_frame(
        &mut self,
    ) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
        self.read_frame()
    }

    /// Writes one bounded post-readiness control response.
    pub(crate) fn write_control_frame(&mut self, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
        self.write_frame(frame)
    }

    #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
    pub(super) fn control_frame_ready(&self) -> Result<bool, LaunchAuthorityError> {
        use std::os::fd::AsRawFd as _;

        let mut byte = [0_u8; 1];
        match nix::sys::socket::recv(
            self.stream.as_raw_fd(),
            &mut byte,
            nix::sys::socket::MsgFlags::MSG_PEEK | nix::sys::socket::MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(0) => Err(LaunchAuthorityError::ProtectedChannelUnavailable),
            Ok(_) => Ok(true),
            Err(nix::errno::Errno::EAGAIN) => Ok(false),
            Err(_) => Err(LaunchAuthorityError::ProtectedChannelUnavailable),
        }
    }

    #[cfg(any(feature = "desktop-protected", feature = "test-support"))]
    pub(super) fn enter_control_loop(&self) -> Result<(), LaunchAuthorityError> {
        self.stream
            .set_read_timeout(Some(CONTROL_IDLE_TIMEOUT))
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)
    }

    #[cfg(all(unix, feature = "desktop-protected"))]
    pub(super) fn root_handle_endpoint(
        &self,
        authenticator: RootHandleTransferAuthenticator,
        context: &runne_api::RootHandleTransferContext,
        offer_digest: [u8; 32],
    ) -> Result<runne_platform_desktop::ProtectedRootHandleEndpoint, LaunchAuthorityError> {
        runne_platform_desktop::ProtectedRootHandleEndpoint::from_owned_protected_channel(
            self.stream
                .try_clone()
                .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?,
            authenticator,
            context,
            offer_digest,
        )
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
    }

    #[cfg(all(unix, feature = "desktop-protected"))]
    #[allow(clippy::needless_return)]
    pub(super) fn peer_identity(&self) -> Result<(u32, u32), LaunchAuthorityError> {
        #[cfg(target_os = "linux")]
        {
            let peer = rustix::net::sockopt::socket_peercred(&self.stream)
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
            let pid = u32::try_from(peer.pid.as_raw_pid())
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
            return Ok((pid, peer.uid.as_raw() as u32));
        }
        #[cfg(target_os = "macos")]
        {
            let pid =
                nix::sys::socket::getsockopt(&self.stream, nix::sys::socket::sockopt::LocalPeerPid)
                    .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
            let credentials = nix::sys::socket::getsockopt(
                &self.stream,
                nix::sys::socket::sockopt::LocalPeerCred,
            )
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
            return u32::try_from(pid)
                .map(|pid| (pid, credentials.uid()))
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch);
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(LaunchAuthorityError::UnsupportedPlatformBackend)
    }
}

#[cfg(all(windows, feature = "desktop-protected"))]
impl ProtectedActivationChannel {
    pub(super) fn root_handle_endpoint(
        &self,
        _authenticator: RootHandleTransferAuthenticator,
        context: &runne_api::RootHandleTransferContext,
        offer_digest: [u8; 32],
    ) -> Result<runne_platform_desktop::ProtectedRootHandleEndpoint, LaunchAuthorityError> {
        runne_platform_desktop::ProtectedRootHandleEndpoint::from_owned_protected_channel(
            self.stream
                .try_clone()
                .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?,
            context,
            offer_digest,
        )
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
    }

    pub(super) fn peer_identity(&self) -> Result<(u32, u32), LaunchAuthorityError> {
        runne_windows_native_handle::named_pipe_peer_process_id(&self.stream)
            .map(|process_id| (process_id, 0))
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
    }
}

#[cfg(not(any(unix, windows)))]
pub struct ProtectedActivationChannel;

#[cfg(not(any(unix, windows)))]
impl ProtectedActivationChannel {
    pub fn from_inherited_stdin() -> Result<Option<Self>, LaunchAuthorityError> {
        Ok(None)
    }
}
