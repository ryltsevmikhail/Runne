//! Draft test-only bounded local channel; no public transport conformance claim.
use super::clock::Deadline;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const CAP: usize = 16_384;

fn pause(deadline: Deadline) -> io::Result<()> {
    let left = deadline.try_remaining().map_err(|_| io::ErrorKind::TimedOut)?;
    std::thread::sleep(left.min(Duration::from_millis(1)));
    Ok(())
}

fn read_all(stream: &mut UnixStream, bytes: &mut [u8], deadline: Deadline) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        deadline.try_remaining().map_err(|_| io::ErrorKind::TimedOut)?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => pause(deadline)?,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub(super) fn send(stream: &mut UnixStream, body: &[u8], deadline: Deadline) -> io::Result<()> {
    send_observed(stream, body, deadline, || {})
}

// Test observation is invoked only after this send's actual WouldBlock syscall.
fn send_observed(
    stream: &mut UnixStream, body: &[u8], deadline: Deadline, mut blocked: impl FnMut(),
) -> io::Result<()> {
    if body.is_empty() || body.len() > CAP {
        return Err(io::ErrorKind::InvalidData.into());
    }
    stream.set_nonblocking(true)?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    let mut offset = 0;
    while offset < frame.len() {
        deadline.try_remaining().map_err(|_| io::ErrorKind::TimedOut)?;
        match stream.write(&frame[offset..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => { blocked(); pause(deadline)?; },
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// The sender must shutdown its write half. A second/partial extra frame fails.
// In the history, request and result are opposite directions of this stream;
// commit-cut observations and crash permission use a DISTINCT control channel.
pub(super) fn receive(stream: &mut UnixStream, deadline: Deadline) -> io::Result<Vec<u8>> {
    stream.set_nonblocking(true)?;
    let mut prefix = [0; 4];
    read_all(stream, &mut prefix, deadline)?;
    let size = u32::from_be_bytes(prefix) as usize;
    if size == 0 || size > CAP {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut body = vec![0; size];
    read_all(stream, &mut body, deadline)?;
    require_eof_without_bytes(stream, deadline)?;
    Ok(body)
}

// Must be called while the original owner is independently observed live.
// EOF here is failure; this is a local no-buffered-byte observation, not proof
// that the owner can never send later. Final EOF check after collection closes it.
pub(super) fn no_result_yet(stream: &mut UnixStream, deadline: Deadline) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    loop {
        deadline.try_remaining().map_err(|_| io::ErrorKind::TimedOut)?;
        let mut byte = [0];
        match stream.read(&mut byte) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

// Only success is actual EOF with zero intervening bytes. Any byte, including
// an incomplete RESULT prefix, refuses lost-ACK qualification.
pub(super) fn require_eof_without_bytes(stream: &mut UnixStream, deadline: Deadline) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    loop {
        deadline.try_remaining().map_err(|_| io::ErrorKind::TimedOut)?;
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => pause(deadline)?,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
#[path = "channel_tests.rs"]
mod tests;
