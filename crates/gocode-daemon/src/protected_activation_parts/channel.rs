/// Owned daemon side of the inherited full-duplex activation channel.
#[cfg(unix)]
pub struct ProtectedActivationChannel {
    stream: std::os::unix::net::UnixStream,
}

#[cfg(unix)]
impl ProtectedActivationChannel {
    /// Wraps the inherited child endpoint and installs bounded I/O deadlines.
    pub fn new(stream: std::os::unix::net::UnixStream) -> Result<Self, LaunchAuthorityError> {
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

    fn read_frame(&mut self) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
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

    fn write_frame(&mut self, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
        if frame.len() < 5 || frame.len() > MAX_FRAME_PAYLOAD_BYTES + 4 {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.stream
            .write_all(frame)
            .and_then(|()| self.stream.flush())
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)
    }

    /// Reads the next bounded frame for the post-readiness control loop.
    pub fn read_control_frame(&mut self) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
        self.read_frame()
    }

    /// Writes one bounded post-readiness control response.
    pub fn write_control_frame(&mut self, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
        self.write_frame(frame)
    }
}
