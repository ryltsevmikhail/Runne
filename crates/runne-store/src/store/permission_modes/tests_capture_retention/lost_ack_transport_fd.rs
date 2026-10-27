//! Draft safe stdio socket handoff for closed, no-exec/no-fork guard roles.
use std::{io, os::{fd::{AsFd, OwnedFd}, unix::net::UnixStream},
    process::{Child, Command, Stdio}, sync::atomic::{AtomicBool, Ordering}};
static TAKEN: AtomicBool = AtomicBool::new(false);

// The exact constructor supplies a fresh Command with stdout null. Libtest's
// stdout never reaches control. Unexpected stderr bytes refuse the protocol.
// Consume Command so parent aliases close before either returned spawn result.
pub(super) fn spawn(
    mut command: Command, data: UnixStream, control: UnixStream,
) -> io::Result<Child> {
    let data: OwnedFd = data.into();
    let control: OwnedFd = control.into();
    command.stdin(Stdio::from(data)).stderr(Stdio::from(control));
    let result = command.spawn();
    drop(command);
    result
}

// Safe owned duplicates; never adopt raw numbers or remove another Rust owner.
// Called only once after dedicated role/context admission. Original stdin/stderr
// endpoints remain process-owned until exit: guard roles MUST NOT exec/fork.
// Native-effect role integration is NOT qualified by this transport.
pub(super) fn take_inherited() -> io::Result<(UnixStream, UnixStream)> {
    if TAKEN.swap(true, Ordering::SeqCst) { return Err(io::ErrorKind::InvalidData.into()); }
    let data = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    let control = UnixStream::from(std::io::stderr().as_fd().try_clone_to_owned()?);
    for stream in [&data, &control] {
        // Safe socket operations refuse non-sockets/disconnected/non-Unix peers.
        if !stream.local_addr()?.is_unnamed() || !stream.peer_addr()?.is_unnamed() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        stream.set_nonblocking(true)?;
    }
    Ok((data, control))
}
