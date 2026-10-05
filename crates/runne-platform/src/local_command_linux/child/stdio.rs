use super::output::OutputCapture;
use crate::local_command_linux::io::LinuxCommandOutputLimitsV1;
use crate::local_command_linux::spec::LinuxCommandError;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(in crate::local_command_linux) struct CommandStdio {
    pub(super) child_fds: [OwnedFd; 3],
    pub(super) output: Option<OutputCapture>,
}

impl CommandStdio {
    pub(in crate::local_command_linux) fn discard() -> Result<Self, LinuxCommandError> {
        let null = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|_| LinuxCommandError::Unavailable)?;
        Ok(Self {
            child_fds: [clone_fd(&null)?, clone_fd(&null)?, OwnedFd::from(null)],
            output: None,
        })
    }

    pub(in crate::local_command_linux) fn bounded(
        input: &[u8],
        limits: LinuxCommandOutputLimitsV1,
    ) -> Result<Self, LinuxCommandError> {
        let stdin = sealed_input(input)?;
        let (stdout_read, stdout_write) = output_pipe()?;
        let (stderr_read, stderr_write) = output_pipe()?;
        Ok(Self {
            child_fds: [stdin, stdout_write, stderr_write],
            output: Some(OutputCapture::new(stdout_read, stderr_read, limits)),
        })
    }
}

fn sealed_input(input: &[u8]) -> Result<OwnedFd, LinuxCommandError> {
    if input.len() > crate::local_command_linux::io::MAX_STDIN_BYTES {
        return Err(LinuxCommandError::Invalid);
    }
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"runne-command-input".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(LinuxCommandError::Unavailable);
    }
    let mut file = unsafe { File::from_raw_fd(raw as i32) };
    file.write_all(input)
        .map_err(|_| LinuxCommandError::Unavailable)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    let added = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) };
    let actual = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if added != 0 || actual < 0 || actual & seals != seals {
        return Err(LinuxCommandError::Unavailable);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxCommandError::Unavailable)?;
    Ok(file.into())
}

fn output_pipe() -> Result<(File, OwnedFd), LinuxCommandError> {
    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(LinuxCommandError::Unavailable);
    }
    let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let flags = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
    {
        return Err(LinuxCommandError::Unavailable);
    }
    Ok((File::from(read), write))
}

fn clone_fd(file: &File) -> Result<OwnedFd, LinuxCommandError> {
    file.try_clone()
        .map(Into::into)
        .map_err(|_| LinuxCommandError::Unavailable)
}
