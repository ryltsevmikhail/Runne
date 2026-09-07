//! Artifact descriptor intake: exactly one CLOEXEC-verified fd bound to
//! the `load_model` frame's declared digest/length. All reads are safe
//! rustix calls over the owned descriptor (workspace forbids `unsafe`).

use crate::error::HostError;

pub fn take_single_fd(
    fds: &mut Vec<rustix::fd::OwnedFd>,
) -> Result<std::os::fd::OwnedFd, HostError> {
    if fds.len() > 1 {
        fds.clear();
        return Err(HostError::FdDuplicate);
    }
    if fds.len() != 1 {
        fds.clear();
        return Err(HostError::FdMissing);
    }
    Ok(fds.remove(0))
}

/// Safe bounded read over the owned descriptor at `offset` (magic and
/// bounded header checks by the backend; no allocation from counts).
pub fn read_at(fd: &rustix::fd::OwnedFd, offset: u64, buf: &mut [u8]) -> Result<(), HostError> {
    let mut done = 0usize;
    rustix::fs::seek(fd, rustix::fs::SeekFrom::Start(offset))
        .map_err(|_| HostError::CorruptModel)?;
    while done < buf.len() {
        let n = rustix::io::read(fd, &mut buf[done..]).map_err(|_| HostError::CorruptModel)?;
        if n == 0 {
            return Err(HostError::CorruptModel);
        }
        done += n;
    }
    Ok(())
}
