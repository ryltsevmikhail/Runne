use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
use runne_platform_ports::provider_credential_prompt::CredentialPipeBytes;
use rustix::pipe::{PipeFlags, pipe_with};

const MAX_CONTROL_FRAME_BYTES: usize = 4 * 1024;

/// Tauri-owned halves of one writer's inherited control and secret channels.
///
/// The control endpoint is retained for authenticated daemon handoff. The
/// secret pipe has a single write operation and is closed immediately after it.
pub struct UnixWriterBrokerEndpoints {
    control: UnixStream,
    secret: Option<File>,
}

/// Private child-side handles consumed while configuring the exact writer.
pub struct UnixWriterChildChannels {
    control: UnixStream,
    secret: File,
}

impl UnixWriterBrokerEndpoints {
    /// Creates fresh, non-serializable inherited endpoints for one child.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when either native endpoint cannot be created.
    pub fn pair() -> Result<(Self, UnixWriterChildChannels), BrokerHandoffError> {
        let (parent_control, child_control) =
            UnixStream::pair().map_err(|_| BrokerHandoffError::Unavailable)?;
        let (child_secret, parent_secret) = secret_pipe()?;
        Ok((
            Self {
                control: parent_control,
                secret: Some(parent_secret),
            },
            UnixWriterChildChannels {
                control: child_control,
                secret: child_secret,
            },
        ))
    }

    /// Writes a broker-control frame to the retained endpoint.
    ///
    /// Frame validation and peer authentication remain the daemon and writer
    /// responsibilities; this adapter does not interpret the bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the endpoint is no longer writable.
    pub fn send_control(&mut self, frame: &[u8]) -> Result<(), BrokerHandoffError> {
        self.control
            .write_all(frame)
            .and_then(|()| self.control.flush())
            .map_err(|_| BrokerHandoffError::Unavailable)
    }

    /// Reads one exact-size broker-control response from the retained endpoint.
    ///
    /// The caller selects the fixed bounded frame size before this transport
    /// adapter reads any byte.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for an empty requested frame or an unavailable endpoint.
    pub fn read_control_exact(&mut self, length: usize) -> Result<Vec<u8>, BrokerHandoffError> {
        if length == 0 || length > MAX_CONTROL_FRAME_BYTES {
            return Err(BrokerHandoffError::Rejected);
        }
        let mut frame = vec![0; length];
        self.control
            .read_exact(&mut frame)
            .map_err(|_| BrokerHandoffError::Unavailable)?;
        Ok(frame)
    }

    /// Sends one bounded secret line and irrevocably closes the write end.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the pipe is unavailable or was used before.
    pub fn send_secret(&mut self, material: CredentialPipeBytes) -> Result<(), BrokerHandoffError> {
        let mut secret = self.secret.take().ok_or(BrokerHandoffError::Rejected)?;
        let result = secret
            .write_all(material.as_bytes())
            .and_then(|()| secret.write_all(b"\n"))
            .and_then(|()| secret.flush())
            .map_err(|_| BrokerHandoffError::Unavailable);
        drop(material);
        result
    }
}

/// Binds inherited control to stdin and the secret read end to stdout.
///
/// The supplied command must originate from [`super::writer_command`]. This
/// function has no parameters for argv or environment values.
///
/// # Errors
///
/// Returns a closed failure only when the native descriptor contract is invalid.
pub fn configure_unix_writer_channels(
    command: &mut Command,
    channels: UnixWriterChildChannels,
) -> Result<(), BrokerHandoffError> {
    let control_stderr = channels
        .control
        .try_clone()
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    command.stdin(Stdio::from(OwnedFd::from(channels.control)));
    command.stderr(Stdio::from(OwnedFd::from(control_stderr)));
    command.stdout(Stdio::from(OwnedFd::from(channels.secret)));
    Ok(())
}

fn secret_pipe() -> Result<(File, File), BrokerHandoffError> {
    let (read, write) = pipe_with(PipeFlags::CLOEXEC).map_err(|_| BrokerHandoffError::Unavailable)?;
    Ok((File::from(read), File::from(write)))
}
