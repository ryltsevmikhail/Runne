use std::num::NonZeroU32;
use std::os::fd::AsFd;

use nix::sys::socket::{getsockopt, sockopt};
use nix::sys::stat::fstat;

use crate::{MacOsProcessStartIdentity, peer_kill};

/// Opaque kernel-captured local Unix peer identity.
pub struct MacOsLocalPeerProcessIdentity {
    token: nix::sys::socket::audit_token_t,
    pid: NonZeroU32,
    process_start_digest: [u8; 32],
    euid: u32,
    socket_identity: (i32, u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsLocalPeerProcessIdentityError {
    Rejected,
    Unavailable,
}

impl MacOsLocalPeerProcessIdentity {
    pub(super) fn copy_guest_code(
        &self,
    ) -> Result<
        security_framework::os::macos::code_signing::SecCode,
        crate::MacOsPackagedWriterObservationError,
    > {
        crate::packaged_writer_observation::security_code::guest_from_audit_token(&self.token)
    }

    /// # Errors
    ///
    /// Returns a closed error when kernel peer evidence is incomplete or mismatched.
    pub fn capture<S: AsFd>(stream: &S) -> Result<Self, MacOsLocalPeerProcessIdentityError> {
        let token = getsockopt(stream, sockopt::LocalPeerToken)
            .map_err(|_| MacOsLocalPeerProcessIdentityError::Rejected)?;
        let pid = getsockopt(stream, sockopt::LocalPeerPid)
            .map_err(|_| MacOsLocalPeerProcessIdentityError::Rejected)?;
        let pid = NonZeroU32::new(
            u32::try_from(pid).map_err(|_| MacOsLocalPeerProcessIdentityError::Rejected)?,
        )
        .ok_or(MacOsLocalPeerProcessIdentityError::Rejected)?;
        let credentials = getsockopt(stream, sockopt::LocalPeerCred)
            .map_err(|_| MacOsLocalPeerProcessIdentityError::Rejected)?;
        let euid = peer_kill::effective_uid();
        peer_kill::token_matches_peer(&token, pid, credentials.uid(), euid)
            .then_some(())
            .ok_or(MacOsLocalPeerProcessIdentityError::Rejected)?;
        let process_start_digest = MacOsProcessStartIdentity::observe(pid)
            .map_err(|_| MacOsLocalPeerProcessIdentityError::Rejected)?
            .digest();
        let socket_identity = socket_identity(stream)?;
        Ok(Self {
            token,
            pid,
            process_start_digest,
            euid,
            socket_identity,
        })
    }

    #[must_use]
    pub const fn pid(&self) -> NonZeroU32 {
        self.pid
    }
    #[must_use]
    pub const fn process_start_digest(&self) -> [u8; 32] {
        self.process_start_digest
    }
    #[must_use]
    pub const fn euid(&self) -> u32 {
        self.euid
    }

    /// # Errors
    ///
    /// Returns a closed error when the stream no longer names the captured peer.
    pub fn revalidate_same_peer<S: AsFd>(
        &self,
        stream: &S,
    ) -> Result<(), MacOsLocalPeerProcessIdentityError> {
        let fresh = Self::capture(stream)?;
        (peer_kill::same_audit_token(&self.token, &fresh.token)
            && fresh.pid == self.pid
            && fresh.euid == self.euid
            && fresh.process_start_digest == self.process_start_digest
            && fresh.socket_identity == self.socket_identity)
            .then_some(())
            .ok_or(MacOsLocalPeerProcessIdentityError::Rejected)
    }
}

fn socket_identity<S: AsFd>(stream: &S) -> Result<(i32, u64), MacOsLocalPeerProcessIdentityError> {
    let stat = fstat(stream).map_err(|_| MacOsLocalPeerProcessIdentityError::Rejected)?;
    Ok((stat.st_dev, stat.st_ino))
}

impl std::fmt::Debug for MacOsLocalPeerProcessIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacOsLocalPeerProcessIdentity(<kernel-local-peer>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn current_kernel_local_peer_is_complete_and_revalidates() {
        let (local, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let identity = MacOsLocalPeerProcessIdentity::capture(&local).unwrap();

        assert_eq!(identity.pid().get(), std::process::id());
        assert_ne!(identity.process_start_digest(), [0; 32]);
        assert_eq!(identity.euid(), peer_kill::effective_uid());
        assert!(identity.revalidate_same_peer(&local).is_ok());
    }

    #[test]
    fn another_socket_is_not_the_captured_peer() {
        let (first, _first_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (second, _second_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let identity = MacOsLocalPeerProcessIdentity::capture(&first).unwrap();

        assert!(identity.revalidate_same_peer(&second).is_err());
    }

    #[test]
    fn exited_peer_is_not_revalidated() {
        let path = std::path::PathBuf::from("/tmp")
            .join(format!("gocode-local-peer-{}", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("local_peer::tests::peer_exit_helper")
            .env("GOCODE_LOCAL_PEER_EXIT_SOCKET", &path)
            .spawn()
            .unwrap();
        let (stream, _) = listener.accept().unwrap();
        let identity = MacOsLocalPeerProcessIdentity::capture(&stream).unwrap();

        assert!(child.wait().unwrap().success());
        assert!(identity.revalidate_same_peer(&stream).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn peer_exit_helper() {
        let Ok(path) = std::env::var("GOCODE_LOCAL_PEER_EXIT_SOCKET") else {
            return;
        };
        let _stream = std::os::unix::net::UnixStream::connect(path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
