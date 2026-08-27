use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};

use rand::RngCore;
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
use runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec;
use runne_platform_ports::provider_credential_prompt::CredentialPipeBytes;
use rustix::pipe::{PipeFlags, pipe_with};
use sha2::{Digest, Sha256};

use super::{RetainedWriterProcess, WriterProcessEvidence, writer_command};

const MAX_CONTROL_FRAME_BYTES: usize = 4 * 1024;

/// Tauri-owned halves of one writer's inherited control and secret channels.
///
/// The control endpoint is retained for authenticated daemon handoff. The
/// secret pipe has a single write operation and is closed immediately after it.
pub struct UnixWriterBrokerEndpoints {
    control: Option<UnixStream>,
    secret: Option<File>,
    channel_binding: [u8; 32],
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
        let mut channel_binding = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut channel_binding);
        if channel_binding == [0; 32] {
            return Err(BrokerHandoffError::Unavailable);
        }
        Ok((
            Self {
                control: Some(parent_control),
                secret: Some(parent_secret),
                channel_binding,
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
        let control = self.control.as_mut().ok_or(BrokerHandoffError::Rejected)?;
        control
            .write_all(frame)
            .and_then(|()| control.flush())
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
            .as_mut()
            .ok_or(BrokerHandoffError::Rejected)?
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

    pub(crate) const fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    pub(super) fn take_control_for_handoff(&mut self) -> Result<UnixStream, BrokerHandoffError> {
        self.control.take().ok_or(BrokerHandoffError::Rejected)
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
    let (read, write) =
        pipe_with(PipeFlags::CLOEXEC).map_err(|_| BrokerHandoffError::Unavailable)?;
    Ok((File::from(read), File::from(write)))
}

/// Exact desktop-held Unix child. The `Child` remains the only kill/reap target.
pub struct UnixRetainedWriterProcess {
    child: Child,
    start_identity: [u8; 32],
}

impl UnixRetainedWriterProcess {
    fn from_spawned(mut child: Child) -> Result<Self, BrokerHandoffError> {
        let start_identity = match observed_start_identity(child.id()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        Ok(Self {
            child,
            start_identity,
        })
    }
}

impl RetainedWriterProcess for UnixRetainedWriterProcess {
    fn writer_start_identity(&self) -> Result<[u8; 32], BrokerHandoffError> {
        (observed_start_identity(self.child.id())? == self.start_identity)
            .then_some(self.start_identity)
            .ok_or(BrokerHandoffError::Rejected)
    }

    fn terminate_retained_child(&mut self) -> Result<(), BrokerHandoffError> {
        let _ = self.writer_start_identity()?;
        self.child
            .kill()
            .map_err(|_| BrokerHandoffError::Unavailable)
    }

    fn reap_retained_child(&mut self) -> Result<(), BrokerHandoffError> {
        self.child
            .wait()
            .map(|_| ())
            .map_err(|_| BrokerHandoffError::Unavailable)
    }
}

/// Directly launches the measured writer with fresh inherited channels.
///
/// The returned endpoint remains non-serializable. Its fresh binding is only
/// a handoff nonce; the later daemon transfer must authenticate that binding.
///
/// # Errors
///
/// Returns a closed failure when the measured child, its inherited channels,
/// or its kernel-observed start identity cannot be established.
pub fn spawn_unix_writer(
    spec: &VerifiedWriterLaunchSpec,
) -> Result<
    (
        UnixWriterBrokerEndpoints,
        UnixRetainedWriterProcess,
        WriterProcessEvidence,
    ),
    BrokerHandoffError,
> {
    let (endpoints, child_channels) = UnixWriterBrokerEndpoints::pair()?;
    let mut command = writer_command(spec);
    configure_unix_writer_channels(&mut command, child_channels)?;
    let child = command
        .spawn()
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let process = UnixRetainedWriterProcess::from_spawned(child)?;
    let evidence = WriterProcessEvidence::from_native_writer(
        process.writer_start_identity()?,
        spec.artifact().image_digest(),
        endpoints.channel_binding(),
    )?;
    Ok((endpoints, process, evidence))
}

#[cfg(target_os = "linux")]
fn observed_start_identity(pid: u32) -> Result<[u8; 32], BrokerHandoffError> {
    let process_stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let tail = process_stat
        .rsplit_once(')')
        .map(|(_, tail)| tail)
        .ok_or(BrokerHandoffError::Rejected)?;
    let start_time = tail
        .split_whitespace()
        .nth(19)
        .ok_or(BrokerHandoffError::Rejected)?;
    let mut digest = Sha256::new();
    digest.update(b"gocode.provider-credential-writer.start.v1");
    digest.update(pid.to_be_bytes());
    digest.update(start_time.as_bytes());
    Ok(digest.finalize().into())
}

#[cfg(not(target_os = "linux"))]
fn observed_start_identity(_pid: u32) -> Result<[u8; 32], BrokerHandoffError> {
    Err(BrokerHandoffError::Unavailable)
}
